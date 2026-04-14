/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "json-stream.h"
#include "log.h"
#include "string-table.h"
#include "string-util.h"

#include "ovsdb-client.h"
#include "ovsdb-monitor.h"
#include "ovsdb-rpc.h"
#include "ovsdb-schema.h"

struct OVSDBClient {
        unsigned n_ref;
        sd_event *event;
        char *socket_path;
        JsonStream stream;
        bool stream_initialized;

        OVSDBClientState state;
        OVSDBRpcLayer rpc;
        OVSDBMonitor *monitor;
        sd_json_variant *schema;

        ovsdb_state_cb_t state_cb;
        void *state_userdata;
        ovsdb_notify_cb_t notify_cb;
        void *notify_userdata;
        ovsdb_update_cb_t update_cb;
        void *update_userdata;
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

        /* Cancel all in-flight RPC requests when entering FAILED state */
        if (new_state == OVSDB_CLIENT_FAILED) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *synthetic_error = NULL;

                if (sd_json_buildo(
                                &synthetic_error,
                                SD_JSON_BUILD_PAIR_STRING("error", "connection failed")) < 0)
                        (void) sd_json_variant_new_string(&synthetic_error, "connection failed");

                ovsdb_rpc_layer_cancel_all(&c->rpc, c, synthetic_error);
        }

        if (c->state_cb)
                return c->state_cb(c, old_state, new_state, c->state_userdata);

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

        sd_json_variant_unref(client->schema);
        client->schema = sd_json_variant_ref(result);

        return ovsdb_client_set_state(client, OVSDB_CLIENT_READY);
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

                r = json_stream_parse(&c->stream, &message);
                if (r < 0) {
                        log_debug_errno(r, "OVSDB client: parse error: %m");
                        return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                }
                if (r == 0)
                        break; /* no more complete messages */

                /* Handle echo requests in-place — we have both the message and the stream here.
                 * The server sends {"method":"echo","params":[],"id":N} and expects a reply
                 * with the params echoed back. Not replying causes the server to disconnect. */
                sd_json_variant *method_v = sd_json_variant_by_key(message, "method");
                sd_json_variant *id_v = sd_json_variant_by_key(message, "id");
                if (method_v && sd_json_variant_is_string(method_v) &&
                    streq(sd_json_variant_string(method_v), "echo") &&
                    id_v && !sd_json_variant_is_null(id_v)) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL, *empty_array = NULL;
                        sd_json_variant *params_v = sd_json_variant_by_key(message, "params");

                        if (!params_v) {
                                r = sd_json_variant_new_array(&empty_array, NULL, 0);
                                if (r < 0) {
                                        log_debug_errno(r, "OVSDB client: failed to build empty echo params: %m");
                                        continue;
                                }
                                params_v = empty_array;
                        }

                        r = sd_json_buildo(&reply,
                                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id_v)),
                                        SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(params_v)),
                                        SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_NULL));
                        if (r < 0) {
                                log_debug_errno(r, "OVSDB client: failed to build echo reply: %m");
                                return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                        }
                        r = json_stream_enqueue(&c->stream, reply);
                        if (r < 0) {
                                /* Failure to send the echo reply means ovsdb-server's 5s probe
                                 * timer will fire and the server will close the connection. Don't
                                 * wait for that timeout — fail fast and let the manager rebuild. */
                                log_debug_errno(r, "OVSDB client: failed to enqueue echo reply: %m");
                                return ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                        }
                        continue;
                }

                r = ovsdb_rpc_layer_dispatch(
                                &c->rpc,
                                c,
                                message,
                                c->notify_cb,
                                c->notify_userdata);
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

        ovsdb_rpc_layer_init(&c->rpc);

        r = json_stream_init(
                        &c->stream,
                        &(JsonStreamParams) {
                                .phase = ovsdb_client_phase,
                                .dispatch = ovsdb_client_dispatch,
                                .userdata = c,
                        });
        if (r < 0)
                return r;

        json_stream_set_flags(&c->stream, JSON_STREAM_DELIMITERLESS, true);
        c->stream_initialized = true;

        *ret = TAKE_PTR(c);
        return 0;
}

int ovsdb_client_new_from_fd(OVSDBClient **ret, sd_event *event, int fd) {
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        int r;

        assert(ret);
        assert(event);
        assert(fd >= 0);

        r = ovsdb_client_init_common(&c, event);
        if (r < 0)
                return r;

        r = json_stream_connect_fd_pair(&c->stream, fd, fd);
        if (r < 0)
                return r;

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

OVSDBClient* ovsdb_client_ref(OVSDBClient *c) {
        if (!c)
                return NULL;

        assert(c->n_ref > 0);
        c->n_ref++;

        return c;
}

OVSDBClient* ovsdb_client_unref(OVSDBClient *c) {
        if (!c)
                return NULL;

        assert(c->n_ref > 0);
        c->n_ref--;
        if (c->n_ref > 0)
                return NULL;

        /* Prevent re-entrant unref from state callback during teardown */
        c->state_cb = NULL;
        c->notify_cb = NULL;
        c->update_cb = NULL;

        /* Fire cancel_all BEFORE json_stream_done so per-request callbacks observe
         * a still-functional client (rpc layer alive, stream attached). After this
         * point the client is being torn down and any callback re-entry would
         * touch freed/nulled fields. */
        ovsdb_rpc_layer_cancel_all(&c->rpc, c, /* synthetic_error= */ NULL);

        if (c->stream_initialized) {
                json_stream_detach_event(&c->stream);
                json_stream_done(&c->stream);
        }

        ovsdb_rpc_layer_done(&c->rpc);
        ovsdb_monitor_free(c->monitor);
        sd_json_variant_unref(c->schema);
        sd_event_unref(c->event);
        free(c->socket_path);

        return mfree(c);
}

int ovsdb_client_set_state_cb(OVSDBClient *c, ovsdb_state_cb_t cb, void *userdata) {
        assert(c);

        c->state_cb = cb;
        c->state_userdata = userdata;
        return 0;
}

int ovsdb_client_set_notify_cb(OVSDBClient *c, ovsdb_notify_cb_t cb, void *userdata) {
        assert(c);

        c->notify_cb = cb;
        c->notify_userdata = userdata;
        return 0;
}

int ovsdb_client_set_update_cb(OVSDBClient *c, ovsdb_update_cb_t cb, void *userdata) {
        assert(c);

        c->update_cb = cb;
        c->update_userdata = userdata;
        return 0;
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

static int ovsdb_client_send_get_schema(OVSDBClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *message = NULL;
        uint64_t request_id;
        int r;

        assert(c);

        r = sd_json_build(&params,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("Open_vSwitch")));
        if (r < 0)
                return r;

        r = ovsdb_rpc_build_request(
                        &c->rpc,
                        "get_schema",
                        params,
                        ovsdb_client_on_schema_reply,
                        /* userdata= */ NULL,
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
                ovsdb_client_set_state(c, OVSDB_CLIENT_FAILED);
                return r;
        }

        return 0;
}

typedef struct OVSDBMonitorCondContext {
        ovsdb_reply_cb_t initial_cb;
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
                        return ctx->initial_cb(client, NULL, error, ctx->initial_userdata);
                return 0;
        }

        if (!result) {
                log_debug("OVSDB client: monitor_cond returned NULL result");
                if (ctx->initial_cb)
                        return ctx->initial_cb(client, NULL, NULL, ctx->initial_userdata);
                return 0;
        }

        /* Allocate monitor on first successful reply */
        /* Per RFC 7047 §4.1.6 the initial reply carries the full authoritative state.
         * Discard any previous monitor cache so stale rows from a prior subscription
         * (e.g. before a server-initiated drop) don't contaminate the new snapshot. */
        if (client->monitor)
                ovsdb_monitor_free(client->monitor);

        client->monitor = ovsdb_monitor_new();
        if (!client->monitor) {
                if (ctx->initial_cb)
                        (void) ctx->initial_cb(client, NULL, NULL, ctx->initial_userdata);
                return -ENOMEM;
        }

        r = ovsdb_monitor_apply_initial(client->monitor, result);
        if (r < 0) {
                log_debug_errno(r, "OVSDB client: failed to apply initial monitor snapshot: %m");
                /* Drop the partially-applied cache so subsequent update2 notifications
                 * don't compound on top of inconsistent state; reconnect/resubscribe
                 * will get a fresh snapshot. */
                client->monitor = ovsdb_monitor_free(client->monitor);
                if (ctx->initial_cb)
                        (void) ctx->initial_cb(client, NULL, NULL, ctx->initial_userdata);
                return r;
        }

        if (ctx->initial_cb)
                return ctx->initial_cb(client, result, NULL, ctx->initial_userdata);

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

                /* params is ["networkd", {updates}] */
                updates = sd_json_variant_by_index(params, 1);
                if (!updates) {
                        log_debug("OVSDB client: update2 missing updates object");
                        return 0;
                }

                r = ovsdb_monitor_apply_update2(client->monitor, updates);
                if (r < 0)
                        log_debug_errno(r, "OVSDB client: failed to apply update2: %m");
                else if (client->update_cb)
                        client->update_cb(client, client->update_userdata);

                return 0;  /* Don't kill connection on cache failure */

        } else {
                log_debug("OVSDB client: unknown notification method '%s', ignoring", method);
                return 0;
        }
}

int ovsdb_client_call(OVSDBClient *c, const char *method, sd_json_variant *params, ovsdb_reply_cb_t cb, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *message = NULL;
        uint64_t request_id;
        int r;

        assert(c);
        assert(method);

        if (c->state != OVSDB_CLIENT_READY)
                return -ENOTCONN;

        r = ovsdb_rpc_build_request(
                        &c->rpc,
                        method,
                        params,
                        cb,
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

int ovsdb_client_monitor_cond(
                OVSDBClient *c,
                ovsdb_reply_cb_t initial_cb,
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
        ovsdb_client_set_notify_cb(c, ovsdb_client_notify_handler, /* userdata= */ NULL);

        /* Build monitor_cond params:
         *   ["Open_vSwitch", "networkd", {
         *     "Open_vSwitch": [{"columns": ["bridges"]}],
         *     "Bridge": [{"columns": ["name", "ports", "fail_mode", "stp_enable", "external_ids"]}],
         *     "Port": [{"columns": ["name", "interfaces", "tag", "trunks", "external_ids"]}],
         *     "Interface": [{"columns": ["name", "type", "options", "external_ids"]}]
         *   }]
         */
        r = sd_json_build(&params,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("Open_vSwitch"),
                                SD_JSON_BUILD_STRING("networkd"),
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_ARRAY("Open_vSwitch",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                SD_JSON_BUILD_STRING("bridges")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Bridge",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                SD_JSON_BUILD_STRING("name"),
                                                                SD_JSON_BUILD_STRING("ports"),
                                                                SD_JSON_BUILD_STRING("fail_mode"),
                                                                SD_JSON_BUILD_STRING("stp_enable"),
                                                                SD_JSON_BUILD_STRING("external_ids")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Port",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                SD_JSON_BUILD_STRING("name"),
                                                                SD_JSON_BUILD_STRING("interfaces"),
                                                                SD_JSON_BUILD_STRING("tag"),
                                                                SD_JSON_BUILD_STRING("trunks"),
                                                                SD_JSON_BUILD_STRING("external_ids")))),
                                        SD_JSON_BUILD_PAIR_ARRAY("Interface",
                                                SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_ARRAY("columns",
                                                                SD_JSON_BUILD_STRING("name"),
                                                                SD_JSON_BUILD_STRING("type"),
                                                                SD_JSON_BUILD_STRING("options"),
                                                                SD_JSON_BUILD_STRING("external_ids")))))));
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
                ovsdb_reply_cb_t cb,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *db_name = NULL;
        size_t n_ops, n_params;
        int r;

        assert(c);
        assert(ops);

        if (c->state != OVSDB_CLIENT_READY)
                return -ENOTCONN;

        /* Build params array: ["Open_vSwitch", op1, op2, ...] */
        n_ops = sd_json_variant_elements(ops);
        n_params = 1 + n_ops;

        _cleanup_free_ sd_json_variant **elements = NULL;
        elements = new(sd_json_variant*, n_params);
        if (!elements)
                return -ENOMEM;

        r = sd_json_variant_new_string(&db_name, "Open_vSwitch");
        if (r < 0)
                return r;

        elements[0] = db_name;
        for (size_t i = 0; i < n_ops; i++)
                elements[1 + i] = sd_json_variant_by_index(ops, i);

        r = sd_json_variant_new_array(&params, elements, n_params);
        if (r < 0)
                return r;

        return ovsdb_client_call(c, "transact", params, cb, userdata);
}
