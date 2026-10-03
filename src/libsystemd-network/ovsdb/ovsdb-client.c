/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "json-stream.h"
#include "json-util.h"
#include "log.h"
#include "string-table.h"
#include "string-util.h"

#include "ovsdb-client.h"
#include "ovsdb-monitor.h"
#include "ovsdb-rpc.h"
#include "ovsdb-schema.h"

/* Identifier we send as monitor name in monitor_cond, and that the server
 * echoes back as params[0] of every update2 notification. We only ever issue
 * one monitor_cond on a connection, so update2 with a different monitor name
 * is either a server bug or a future second monitor that we don't yet handle. */
#define OVSDB_MONITOR_NAME "networkd"

struct OVSDBClient {
        unsigned n_ref;
        sd_event *event;
        char *socket_path;
        JsonStream stream;
        bool stream_initialized;

        OVSDBClientState state;
        OVSDBRpc rpc;
        OVSDBMonitor *monitor;
        sd_json_variant *schema;

        ovsdb_state_callback_t state_cb;
        ovsdb_notify_callback_t notify_cb;
        ovsdb_update_callback_t update_cb;
        void *userdata;
};

static const char* const ovsdb_client_state_table[_OVSDB_CLIENT_STATE_MAX] = {
        [OVSDB_CLIENT_DISCONNECTED] = "disconnected",
        [OVSDB_CLIENT_HANDSHAKING]  = "handshaking",
        [OVSDB_CLIENT_READY]        = "ready",
        [OVSDB_CLIENT_FAILED]       = "failed",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(ovsdb_client_state, OVSDBClientState);

static int ovsdb_client_set_state(OVSDBClient *c, OVSDBClientState new_state) {
        OVSDBClientState old_state;

        assert(c);

        old_state = c->state;
        if (old_state == new_state)
                return 0;

        log_debug("OVSDB client: state %s -> %s",
                  strnull(ovsdb_client_state_to_string(old_state)),
                  strnull(ovsdb_client_state_to_string(new_state)));

        c->state = new_state;

        /* Cancel all in-flight RPC requests when entering FAILED state. If building
         * the synthetic error fails (OOM), cancel_all copes with a NULL error. */
        if (new_state == OVSDB_CLIENT_FAILED) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *synthetic_error = NULL;

                (void) sd_json_buildo(
                                &synthetic_error,
                                SD_JSON_BUILD_PAIR_STRING("error", "connection failed"));

                ovsdb_rpc_cancel_all(&c->rpc, c, synthetic_error);
        }

        if (c->state_cb)
                return c->state_cb(c, old_state, new_state, c->userdata);

        return 0;
}

static int ovsdb_client_on_schema_reply(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        int r;

        assert(client);

        /* During teardown (unref), cancel_all fires callbacks with error=NULL, result=NULL.
         * If we're no longer in HANDSHAKING state, just ignore the reply silently. */
        if (client->state != OVSDB_CLIENT_HANDSHAKING)
                return 0;

        if (error) {
                log_debug("OVSDB client: get_schema failed with server error");
                return ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
        }

        if (!result) {
                log_debug("OVSDB client: get_schema returned NULL result");
                return ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
        }

        r = ovsdb_schema_validate(result);
        if (r < 0) {
                log_debug_errno(r, "OVSDB client: schema validation failed: %m");
                return ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
        }

        JSON_VARIANT_REPLACE(client->schema, sd_json_variant_ref(result));

        return ovsdb_client_set_state(client, OVSDB_CLIENT_READY);
}

/* OVSDB JSON-RPC sends back-to-back JSON objects with no formal delimiter (servers
 * may emit any whitespace between values, or none). json_stream_parse() requires
 * a delimiter byte to slice messages; substitute it with a thin wrapper around
 * sd_json_parse_continue() that consumes one top-level JSON object from the
 * JsonStream's input buffer. On a complete object the buffer index is advanced
 * past the consumed bytes; on incomplete input we ask the caller to wait for more
 * data, bounded by the stream's buffer_max — beyond that the data is genuinely
 * malformed and we surface -EBADMSG. */
static int ovsdb_stream_parse(JsonStream *s, sd_json_variant **ret) {
        int r;

        assert(s);
        assert(ret);

        if (s->input_buffer_unscanned == 0) {
                *ret = NULL;
                return 0;
        }

        char *begin = s->input_buffer + s->input_buffer_index;
        bool sensitive = json_stream_flags_set(s, JSON_STREAM_INPUT_SENSITIVE);

        /* sd_json_parse_continue() needs a NUL-terminated string. Copy the unscanned
         * region; matches the same pattern as json_stream_parse() for the delimiter
         * path (which writes a NUL over the delimiter byte). For sensitive streams the
         * copy is wiped on free so a later heap reuse cannot leak credentials. */
        _cleanup_(erase_and_freep) char *msg_sensitive = NULL;
        _cleanup_free_ char *msg_plain = NULL;
        char *msg;

        if (sensitive) {
                msg_sensitive = memdup_suffix0(begin, s->input_buffer_size);
                msg = msg_sensitive;
        } else {
                msg_plain = memdup_suffix0(begin, s->input_buffer_size);
                msg = msg_plain;
        }
        if (!msg)
                return -ENOMEM;

        const char *p = msg;
        r = sd_json_parse_continue(&p, SD_JSON_PARSE_MUST_BE_OBJECT, ret,
                                   /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (IN_SET(r, -EINVAL, -ENODATA)) {
                /* sd_json_parse_continue() returns -EINVAL for three distinct cases:
                 *   1. Truncated input (need more bytes to complete the value)
                 *   2. Syntactically malformed JSON
                 *   3. Syntactically valid but non-object top-level value (rejected
                 *      by SD_JSON_PARSE_MUST_BE_OBJECT)
                 * Per RFC 7047 ovsdb-server only sends top-level objects, so case (3)
                 * indicates a buggy/malicious server; cases (2) and (3) cannot become
                 * valid no matter how much data is appended. We treat all three as
                 * "need more data" up to buffer_max — beyond that we give up with
                 * -EBADMSG which drops the connection. The cost is at most one extra
                 * round of buffering for malformed input; the trade-off avoids
                 * double-parsing every well-formed message just to distinguish (1)
                 * from (2)/(3). */
                if (s->input_buffer_size >= s->buffer_max) {
                        s->input_buffer_index = s->input_buffer_size = s->input_buffer_unscanned = 0;
                        return -EBADMSG;
                }
                s->input_buffer_unscanned = 0;
                *ret = NULL;
                return 0;
        }
        if (r < 0) {
                s->input_buffer_index = s->input_buffer_size = s->input_buffer_unscanned = 0;
                return r;
        }

        size_t sz = (size_t) (p - msg);

        if (sensitive)
                explicit_bzero_safe(begin, sz);

        s->input_buffer_size -= sz;
        if (s->input_buffer_size == 0)
                s->input_buffer_index = 0;
        else
                s->input_buffer_index += sz;
        s->input_buffer_unscanned = s->input_buffer_size;
        return 1;
}

static JsonStreamPhase ovsdb_client_phase(void *userdata) {
        OVSDBClient *c = ASSERT_PTR(userdata);

        switch (c->state) {

        case OVSDB_CLIENT_HANDSHAKING:
                return JSON_STREAM_PHASE_AWAITING_REPLY;

        case OVSDB_CLIENT_READY:
                return JSON_STREAM_PHASE_READING;

        default:
                return JSON_STREAM_PHASE_OTHER;
        }
}

/* Handle echo requests in-place — we have both the message and the stream here.
 * The server sends {"method":"echo","params":[],"id":N} and expects a reply
 * with the params echoed back. Not replying causes the server to disconnect.
 * Replies (id/result/error) lack a "method" and fall through to the RPC layer;
 * SD_JSON_ALLOW_EXTENSIONS lets those extra fields pass without a dispatch error.
 *
 * Returns > 0 if the message was an echo request (handled), 0 if it is not an
 * echo request, < 0 on fatal error (caller should fail the connection). */
static int ovsdb_client_handle_echo(OVSDBClient *c, sd_json_variant *message) {
        struct {
                const char *method;
                sd_json_variant *id;
                sd_json_variant *params;
        } echo = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "method", SD_JSON_VARIANT_STRING,          sd_json_dispatch_const_string,  voffsetof(echo, method), 0 },
                { "id",     _SD_JSON_VARIANT_TYPE_INVALID,   sd_json_dispatch_variant_noref, voffsetof(echo, id),     0 },
                { "params", SD_JSON_VARIANT_ARRAY,           sd_json_dispatch_variant_noref, voffsetof(echo, params), 0 },
                {}
        };
        int r;

        assert(c);
        assert(message);

        if (sd_json_dispatch(message, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &echo) < 0 ||
            !streq_ptr(echo.method, "echo") || !echo.id || sd_json_variant_is_null(echo.id))
                return 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *empty_array = NULL;
        sd_json_variant *params = echo.params;

        if (!params) {
                r = sd_json_variant_new_array(&empty_array, NULL, 0);
                if (r < 0) {
                        /* Skip this echo request; the next server probe gets another chance. */
                        log_debug_errno(r, "OVSDB client: failed to build empty echo params: %m");
                        return 1;
                }
                params = empty_array;
        }

        r = sd_json_buildo(&reply,
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(echo.id)),
                        SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(params)),
                        SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_NULL));
        if (r < 0)
                return log_debug_errno(r, "OVSDB client: failed to build echo reply: %m");

        r = json_stream_enqueue(&c->stream, reply);
        if (r < 0)
                /* Failure to send the echo reply means ovsdb-server's 5s probe
                 * timer will fire and the server will close the connection. Don't
                 * wait for that timeout — fail fast and let the manager rebuild. */
                return log_debug_errno(r, "OVSDB client: failed to enqueue echo reply: %m");

        return 1;
}

static int ovsdb_client_dispatch(void *userdata) {
        OVSDBClient *c = ASSERT_PTR(userdata);
        _cleanup_(ovsdb_client_unrefp) _unused_ OVSDBClient *self_ref = ovsdb_client_ref(c);
        int r;

        /* Flush pending output */
        r = json_stream_write(&c->stream);
        if (r < 0) {
                log_debug_errno(r, "OVSDB client: write error: %m");
                return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
        }

        /* Read from the socket */
        r = json_stream_read(&c->stream);
        if (r < 0) {
                log_debug_errno(r, "OVSDB client: read error: %m");
                return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
        }

        /* json_stream_read() returns 1 both on data-received and on EOF/disconnect.
         * Detect the latter (and other transport-level half-close conditions like
         * write-side disconnect or POLLHUP without buffered output) by consulting
         * the stream's own teardown decision. Without this, a peer hangup is silently
         * absorbed and the dispatcher keeps being scheduled on a dead socket. */
        if (json_stream_should_disconnect(&c->stream)) {
                log_debug("OVSDB client: peer disconnected");
                return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
        }

        /* Parse and dispatch all complete messages */
        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *message = NULL;

                /* A reply or update callback in a previous iteration may have
                 * transitioned the client to FAILED (e.g. a downstream consumer that
                 * detected protocol corruption). The self_ref above keeps `c` alive,
                 * but firing further callbacks against a FAILED client violates the
                 * "no calls after teardown" contract that consumers rely on.
                 *
                 * HANDSHAKING is a legitimate state for parsing — that is when we
                 * are waiting for the get_schema reply that drives the transition
                 * to READY. Only bail on terminal states. */
                if (IN_SET(c->state, OVSDB_CLIENT_FAILED, OVSDB_CLIENT_DISCONNECTED))
                        break;

                r = ovsdb_stream_parse(&c->stream, &message);
                if (r < 0) {
                        log_debug_errno(r, "OVSDB client: parse error: %m");
                        return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                }
                if (r == 0)
                        break; /* no more complete messages */

                r = ovsdb_client_handle_echo(c, message);
                if (r < 0)
                        return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                if (r > 0)
                        continue;

                r = ovsdb_rpc_dispatch(
                                &c->rpc,
                                c,
                                message,
                                c->notify_cb,
                                c->userdata);
                if (r == -ENOENT) {
                        log_debug_errno(r, "OVSDB client: unknown reply id, skipping: %m");
                        continue;
                }
                if (r < 0) {
                        log_debug_errno(r, "OVSDB client: dispatch error: %m");
                        return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                }
        }

        return 0;
}

static int ovsdb_client_init_common(OVSDBClient **ret, sd_event *event) {
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        int r;

        assert(ret);
        assert(event);

        c = new(OVSDBClient, 1);
        if (!c)
                return -ENOMEM;

        *c = (OVSDBClient) {
                .n_ref = 1,
                .state = OVSDB_CLIENT_DISCONNECTED,
                .event = sd_event_ref(event),
        };

        ovsdb_rpc_init(&c->rpc);

        /* OVSDB JSON-RPC sends back-to-back JSON objects with no formal delimiter. We
         * use newline as the wire framing delimiter here purely to suppress json-stream's
         * default trailing NUL byte (which would corrupt the JSON stream as seen by
         * ovsdb-server). Whitespace between top-level JSON values is permitted by RFC
         * 8259 and accepted by ovsdb-server's incremental parser; sd_json_parse_continue()
         * on our side likewise skips leading whitespace. */
        r = json_stream_init(
                        &c->stream,
                        &(JsonStreamParams) {
                                .phase = ovsdb_client_phase,
                                .dispatch = ovsdb_client_dispatch,
                                .userdata = c,
                                .delimiter = "\n",
                        });
        if (r < 0)
                return r;

        c->stream_initialized = true;

        (void) json_stream_set_description(&c->stream, "ovsdb");

        *ret = TAKE_PTR(c);
        return 0;
}

int ovsdb_client_new_from_fd(OVSDBClient **ret, sd_event *event, int fd) {
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        _cleanup_close_ int fd_close = fd;
        int r;

        assert(ret);
        assert(event);
        assert(fd >= 0);

        /* The fd is consumed unconditionally: closed on every error path so callers can
         * always do `fd = -EBADF` after the call without risking a leak. We open-code
         * fd_nonblock + json_stream_attach_fds (instead of json_stream_connect_fd_pair)
         * so the ownership boundary is unambiguous — fd_close stays armed until
         * json_stream_attach_fds returns, after which the stream owns the fd. */

        r = ovsdb_client_init_common(&c, event);
        if (r < 0)
                return r;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = json_stream_attach_fds(&c->stream, fd, fd);
        if (r < 0)
                return r;
        TAKE_FD(fd_close);

        r = json_stream_attach_event(&c->stream, event, /* priority= */ 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int ovsdb_client_new(OVSDBClient **ret, sd_event *event, const char *socket_path) {
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        int r;

        assert(ret);
        assert(event);
        assert(socket_path);

        r = ovsdb_client_init_common(&c, event);
        if (r < 0)
                return r;

        c->socket_path = strdup(socket_path);
        if (!c->socket_path)
                return -ENOMEM;

        *ret = TAKE_PTR(c);
        return 0;
}

static OVSDBClient* ovsdb_client_free(OVSDBClient *c) {
        assert(c);

        /* Prevent re-entrant unref from state callback during teardown */
        c->state_cb = NULL;
        c->notify_cb = NULL;
        c->update_cb = NULL;

        /* Fire cancel_all BEFORE json_stream_done so per-request callbacks observe
         * a still-functional client (rpc layer alive, stream attached). After this
         * point the client is being torn down and any callback re-entry would
         * touch freed/nulled fields. */
        ovsdb_rpc_cancel_all(&c->rpc, c, /* synthetic_error= */ NULL);

        if (c->stream_initialized) {
                json_stream_detach_event(&c->stream);
                json_stream_done(&c->stream);
        }

        ovsdb_rpc_done(&c->rpc);
        ovsdb_monitor_free(c->monitor);
        sd_json_variant_unref(c->schema);
        sd_event_unref(c->event);
        free(c->socket_path);

        return mfree(c);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(OVSDBClient, ovsdb_client, ovsdb_client_free);

void ovsdb_client_set_userdata(OVSDBClient *c, void *userdata) {
        assert(c);

        c->userdata = userdata;
}

void ovsdb_client_bind_state_change(OVSDBClient *c, ovsdb_state_callback_t cb) {
        assert(c);

        c->state_cb = cb;
}

void ovsdb_client_bind_notify(OVSDBClient *c, ovsdb_notify_callback_t cb) {
        assert(c);

        c->notify_cb = cb;
}

void ovsdb_client_bind_update(OVSDBClient *c, ovsdb_update_callback_t cb) {
        assert(c);

        c->update_cb = cb;
}

OVSDBClientState ovsdb_client_get_state(const OVSDBClient *c) {
        assert(c);
        return c->state;
}

OVSDBMonitor* ovsdb_client_get_monitor(const OVSDBClient *c) {
        assert(c);
        return c->monitor;
}

sd_json_variant* ovsdb_client_get_schema(const OVSDBClient *c) {
        assert(c);
        return c->schema;
}

/* Build a request, register the reply callback and enqueue it on the stream,
 * unregistering the callback again if enqueuing fails. Does not check the
 * client state — that's up to the callers. */
static int ovsdb_client_enqueue_request(
                OVSDBClient *c,
                const char *method,
                sd_json_variant *params,
                ovsdb_reply_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *message = NULL;
        uint64_t request_id;
        int r;

        assert(c);
        assert(method);

        r = ovsdb_rpc_build_request(
                        &c->rpc,
                        method,
                        params,
                        callback,
                        userdata,
                        &message,
                        &request_id);
        if (r < 0)
                return r;

        r = json_stream_enqueue(&c->stream, message);
        if (r < 0) {
                ovsdb_rpc_cancel_request(&c->rpc, request_id);
                return r;
        }

        return 0;
}

static int ovsdb_client_send_get_schema(OVSDBClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        int r;

        assert(c);

        r = sd_json_build(&params,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("Open_vSwitch")));
        if (r < 0)
                return r;

        return ovsdb_client_enqueue_request(c, "get_schema", params, ovsdb_client_on_schema_reply, /* userdata= */ NULL);
}

int ovsdb_client_start(OVSDBClient *c) {
        int r;

        assert(c);

        /* Protect against re-entrant unref from state callback (FAILED → unref) */
        _cleanup_(ovsdb_client_unrefp) _unused_ OVSDBClient *self_ref = ovsdb_client_ref(c);

        if (c->state != OVSDB_CLIENT_DISCONNECTED)
                return -EALREADY;

        /* If we have a socket path but no fds attached yet, connect now */
        if (c->socket_path) {
                r = json_stream_connect_address(&c->stream, c->socket_path);
                if (r < 0)
                        return r;

                r = json_stream_attach_event(&c->stream, c->event, /* priority= */ 0);
                if (r < 0)
                        return r;
        }

        r = ovsdb_client_set_state(c, OVSDB_CLIENT_HANDSHAKING);
        if (r < 0)
                return r;

        r = ovsdb_client_send_get_schema(c);
        if (r < 0) {
                (void) ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                return r;
        }

        return 0;
}

typedef struct OVSDBMonitorCondContext {
        ovsdb_reply_callback_t initial_cb;
        void *initial_userdata;
} OVSDBMonitorCondContext;

static int ovsdb_client_on_monitor_cond_reply(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        _cleanup_free_ OVSDBMonitorCondContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(client);

        if (error) {
                log_debug("OVSDB client: monitor_cond failed with server error");
                if (ctx->initial_cb)
                        return ctx->initial_cb(client, /* result= */ NULL, error, ctx->initial_userdata);
                return 0;
        }

        if (!result) {
                log_debug("OVSDB client: monitor_cond returned NULL result");
                if (ctx->initial_cb)
                        return ctx->initial_cb(client, /* result= */ NULL, /* error= */ NULL, ctx->initial_userdata);
                return 0;
        }

        /* Allocate monitor on first successful reply */
        /* Per RFC 7047 §4.1.6 the initial reply carries the full authoritative state.
         * Discard any previous monitor cache so stale rows from a prior subscription
         * (e.g. before a server-initiated drop) don't contaminate the new snapshot. */
        ovsdb_monitor_free(client->monitor);
        client->monitor = ovsdb_monitor_new();
        if (!client->monitor) {
                (void) ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
                if (ctx->initial_cb)
                        (void) ctx->initial_cb(client, /* result= */ NULL, /* error= */ NULL, ctx->initial_userdata);
                return -ENOMEM;
        }

        r = ovsdb_monitor_apply_initial(client->monitor, result);
        if (r < 0) {
                log_debug_errno(r, "OVSDB client: failed to apply initial monitor snapshot: %m");
                /* Drop the partially-applied cache so subsequent update2 notifications
                 * don't compound on top of inconsistent state; reconnect/resubscribe
                 * will get a fresh snapshot. */
                client->monitor = ovsdb_monitor_free(client->monitor);
                (void) ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
                if (ctx->initial_cb)
                        (void) ctx->initial_cb(client, /* result= */ NULL, /* error= */ NULL, ctx->initial_userdata);
                return r;
        }

        if (ctx->initial_cb)
                return ctx->initial_cb(client, result, /* error= */ NULL, ctx->initial_userdata);

        return 0;
}

static int ovsdb_client_notify_handler(
                OVSDBClient *client,
                const char *method,
                sd_json_variant *params,
                void *userdata) {

        int r;

        assert(client);
        assert(method);

        if (streq(method, "update2")) {
                sd_json_variant *updates;

                if (!client->monitor) {
                        log_debug("OVSDB client: received update2 but no monitor active, ignoring");
                        return 0;
                }

                if (!params || !sd_json_variant_is_array(params)) {
                        log_debug("OVSDB client: update2 notification missing or invalid params");
                        return 0;
                }

                /* params is [<monitor-name>, {updates}]. Validate params[0] matches
                 * our monitor id so we never apply updates from an unexpected source
                 * (e.g. a future second monitor) to client->monitor's cache. */
                sd_json_variant *mon_id = sd_json_variant_by_index(params, 0);
                if (!mon_id || !sd_json_variant_is_string(mon_id) ||
                    !streq(sd_json_variant_string(mon_id), OVSDB_MONITOR_NAME)) {
                        log_debug("OVSDB client: update2 for unexpected monitor '%s', ignoring",
                                  mon_id && sd_json_variant_is_string(mon_id) ? sd_json_variant_string(mon_id) : "?");
                        return 0;
                }

                updates = sd_json_variant_by_index(params, 1);
                if (!updates) {
                        log_debug("OVSDB client: update2 missing updates object");
                        return 0;
                }

                r = ovsdb_monitor_apply_update2(client->monitor, updates);
                if (r < 0) {
                        /* A partial apply leaves the monitor cache inconsistent (some rows
                         * updated, some not). Rather than keep serving mixed state, drop to
                         * FAILED so the manager reconnects and re-fetches a clean initial
                         * snapshot. */
                        log_warning_errno(r, "OVSDB client: failed to apply update2, reconnecting for a fresh snapshot: %m");
                        return ovsdb_client_set_state(client, OVSDB_CLIENT_FAILED);
                }
                if (client->update_cb)
                        client->update_cb(client, client->userdata);

                return 0;

        } else {
                log_debug("OVSDB client: unknown notification method '%s', ignoring", method);
                return 0;
        }
}

int ovsdb_client_call(OVSDBClient *c, const char *method, sd_json_variant *params, ovsdb_reply_callback_t cb, void *userdata) {
        assert(c);
        assert(method);

        if (c->state != OVSDB_CLIENT_READY)
                return -ENOTCONN;

        return ovsdb_client_enqueue_request(c, method, params, cb, userdata);
}

int ovsdb_client_monitor_cond(
                OVSDBClient *c,
                ovsdb_reply_callback_t initial_cb,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        _cleanup_free_ OVSDBMonitorCondContext *ctx = NULL;
        int r;

        assert(c);

        if (c->state != OVSDB_CLIENT_READY)
                return -ENOTCONN;

        ctx = new(OVSDBMonitorCondContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (OVSDBMonitorCondContext) {
                .initial_cb = initial_cb,
                .initial_userdata = userdata,
        };

        /* Register the internal notification handler for update2 messages.
         * The handler uses client->monitor internally, no external userdata needed. */
        ovsdb_client_bind_notify(c, ovsdb_client_notify_handler);

        /* Build monitor_cond params:
         *   ["Open_vSwitch", OVSDB_MONITOR_NAME, {
         *     "Open_vSwitch": [{"columns": ["bridges"]}],
         *     "Bridge": [{"columns": ["name", "ports", "fail_mode", "stp_enable", "external_ids"]}],
         *     "Port": [{"columns": ["name", "interfaces", "tag", "external_ids"]}],
         *     "Interface": [{"columns": ["name", "type", "options", "external_ids"]}]
         *   }]
         *
         * Port.trunks is deliberately not monitored: it is an integer-set column whose
         * update2 "modify" payload is a set-XOR diff (RFC 7047 §4.1.7), and the cache only
         * understands set-XOR for uuid sets (is_uuid_set_column() in ovsdb-monitor.c). We
         * never read trunks back from the cache — the reconciler always rebuilds it from
         * the configured VLAN bitmap — so subscribing would only risk caching a corrupted
         * value for no benefit.
         */
        r = sd_json_build(&params,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("Open_vSwitch"),
                                SD_JSON_BUILD_STRING(OVSDB_MONITOR_NAME),
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_ARRAY("Open_vSwitch",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                JSON_BUILD_CONST_STRING("bridges")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Bridge",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                JSON_BUILD_CONST_STRING("name"),
                                                                JSON_BUILD_CONST_STRING("ports"),
                                                                JSON_BUILD_CONST_STRING("fail_mode"),
                                                                JSON_BUILD_CONST_STRING("stp_enable"),
                                                                JSON_BUILD_CONST_STRING("external_ids")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Port",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                JSON_BUILD_CONST_STRING("name"),
                                                                JSON_BUILD_CONST_STRING("interfaces"),
                                                                JSON_BUILD_CONST_STRING("tag"),
                                                                JSON_BUILD_CONST_STRING("external_ids")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Interface",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                JSON_BUILD_CONST_STRING("name"),
                                                                JSON_BUILD_CONST_STRING("type"),
                                                                JSON_BUILD_CONST_STRING("options"),
                                                                JSON_BUILD_CONST_STRING("external_ids")))))));
        if (r < 0)
                return r;

        r = ovsdb_client_call(c, "monitor_cond", params, ovsdb_client_on_monitor_cond_reply, ctx);
        if (r < 0)
                return r;

        TAKE_PTR(ctx);
        return 0;
}

int ovsdb_client_transact(
                OVSDBClient *c,
                sd_json_variant *ops,
                ovsdb_reply_callback_t cb,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        int r;

        assert(c);
        assert(ops);

        if (c->state != OVSDB_CLIENT_READY)
                return -ENOTCONN;

        /* Build params array: ["Open_vSwitch", op1, op2, ...] */
        r = sd_json_build(&params,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("Open_vSwitch")));
        if (r < 0)
                return r;

        for (size_t i = 0; i < sd_json_variant_elements(ops); i++) {
                r = sd_json_variant_append_array(&params, sd_json_variant_by_index(ops, i));
                if (r < 0)
                        return r;
        }

        return ovsdb_client_call(c, "transact", params, cb, userdata);
}
