/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "hash-funcs.h"
#include "json-stream.h"
#include "qmp-client.h"
#include "siphash24.h"

typedef enum QmpClientState {
        QMP_CLIENT_HANDSHAKE_INITIAL,           /* waiting for QMP greeting */
        QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED, /* greeting received, sending qmp_capabilities */
        QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT, /* waiting for qmp_capabilities response */
        QMP_CLIENT_RUNNING,                     /* connected, ready for commands */
        QMP_CLIENT_DISCONNECTED,                /* connection closed */
        _QMP_CLIENT_STATE_MAX,
        _QMP_CLIENT_STATE_INVALID = -EINVAL,
} QmpClientState;

#define QMP_CLIENT_STATE_IS_HANDSHAKE(s)               \
        IN_SET(s,                                      \
               QMP_CLIENT_HANDSHAKE_INITIAL,           \
               QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED, \
               QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT)

typedef struct QmpPendingCommand {
        uint64_t id;
        qmp_command_callback_t callback;
        void *userdata;
} QmpPendingCommand;

struct QmpClient {
        unsigned n_ref;

        JsonStream stream;

        sd_event_source *quit_event_source;
        sd_event_source *defer_event_source;

        uint64_t next_id;
        Hashmap *pending_commands;     /* id -> QmpPendingCommand*, for async dispatch */

        qmp_event_callback_t event_callback;
        qmp_disconnect_callback_t disconnect_callback;
        void *userdata;

        unsigned next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

        QmpClientState state;
        sd_json_variant *current;  /* pinned reply for blocking calls (like varlink's v->current) */
};

static void qmp_pending_command_hash_func(const QmpPendingCommand *p, struct siphash *state) {
        siphash24_compress_typesafe(p->id, state);
}

static int qmp_pending_command_compare_func(const QmpPendingCommand *a, const QmpPendingCommand *b) {
        return CMP(a->id, b->id);
}

DEFINE_PRIVATE_HASH_OPS(qmp_pending_command_hash_ops,
                        QmpPendingCommand, qmp_pending_command_hash_func, qmp_pending_command_compare_func);

static void qmp_client_clear(QmpClient *c);

static QmpClient* qmp_client_destroy(QmpClient *c) {
        if (!c)
                return NULL;

        qmp_client_clear(c);

        return mfree(c);
}

DEFINE_PRIVATE_TRIVIAL_REF_FUNC(QmpClient, qmp_client);
DEFINE_TRIVIAL_UNREF_FUNC(QmpClient, qmp_client, qmp_client_destroy);

static void qmp_client_clear_current(QmpClient *c) {
        assert(c);

        c->current = sd_json_variant_unref(c->current);
}

static void qmp_client_dispatch_event(QmpClient *c, sd_json_variant *v) {
        int r;

        assert(c);
        assert(v);

        if (!c->event_callback)
                return;

        struct {
                const char *event;
                sd_json_variant *data;
        } p = {};

        static const sd_json_dispatch_field table[] = {
                { "event", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  voffsetof(p, event), SD_JSON_MANDATORY },
                { "data",  SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(p, data),  0                 },
                {},
        };

        r = sd_json_dispatch(v, table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0) {
                json_stream_log_errno(&c->stream, r, "Failed to dispatch QMP event, ignoring: %m");
                return;
        }

        r = c->event_callback(c, p.event, p.data, c->userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Event callback returned error, ignoring: %m");
}

/* Extract the human-readable description from a QMP error object. We intentionally ignore the
 * "class" field: QEMU deprecated meaningful error classes years ago and now returns "GenericError"
 * for virtually everything. Only the "desc" string carries useful diagnostic information. */
static const char* qmp_extract_error_description(sd_json_variant *v) {

        sd_json_variant *error = sd_json_variant_by_key(v, "error");
        if (!error)
                return NULL;
        sd_json_variant *desc = sd_json_variant_by_key(error, "desc");
        if (desc)
                return sd_json_variant_string(desc);
        return "unspecified error";
}

/* Extract a command response's "id" field, which our client always sends as an unsigned
 * integer. Returns 1 and sets *ret if a valid unsigned id is present; 0 if the response
 * carries no id at all (e.g. JSON-parse error responses emitted before QEMU read the id);
 * -EBADMSG if an id is present but of the wrong JSON type. */
static int qmp_extract_response_id(sd_json_variant *v, uint64_t *ret) {
        sd_json_variant *id_variant;

        assert(v);
        assert(ret);

        id_variant = sd_json_variant_by_key(v, "id");
        if (!id_variant)
                return 0;
        if (!sd_json_variant_is_unsigned(id_variant))
                return -EBADMSG;

        *ret = sd_json_variant_unsigned(id_variant);
        return 1;
}

/* Parse a QMP command response. Returns 0 on success, -EIO on QMP error.
 * On success: *ret_result points to the "return" value, *ret_error_desc is NULL.
 * On QMP error: *ret_result is NULL, *ret_error_desc is the human-readable description. */
static int qmp_parse_response(sd_json_variant *v, sd_json_variant **ret_result, const char **ret_error_desc) {
        const char *desc;

        desc = qmp_extract_error_description(v);
        if (desc) {
                if (ret_result)
                        *ret_result = NULL;
                if (ret_error_desc)
                        *ret_error_desc = desc;
                return -EIO;
        }

        if (ret_result)
                *ret_result = sd_json_variant_by_key(v, "return");
        if (ret_error_desc)
                *ret_error_desc = NULL;
        return 0;
}

static int qmp_client_build_command(QmpClient *c, const char *command, sd_json_variant *arguments, sd_json_variant **ret, uint64_t *ret_id) {
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(ret);
        assert(ret_id);

        id = c->next_id++;

        r = sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("execute", command),
                        SD_JSON_BUILD_PAIR_CONDITION(!!arguments, "arguments", SD_JSON_BUILD_VARIANT(arguments)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", id));
        if (r < 0)
                return r;

        *ret_id = id;
        return 0;
}

/* Dispatch a parsed QMP message from c->current: route command responses to pending async callbacks, and
 * events to the event callback. Returns 1 on successful dispatch to signal "work was done" to the process()
 * loop. Callback errors are logged but not propagated. */
static int qmp_client_dispatch_reply(QmpClient *c) {
        sd_json_variant *result = NULL;
        const char *desc = NULL;
        uint64_t id;
        int error, r;

        assert(c);

        if (!c->current)
                return 0;

        /* Events have an "event" key */
        if (sd_json_variant_by_key(c->current, "event")) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                qmp_client_dispatch_event(c, v);
                return 1;
        }

        /* Command responses carry an "id" matching a request we sent */
        r = qmp_extract_response_id(c->current, &id);
        if (r < 0) {
                qmp_client_clear_current(c);
                return json_stream_log_errno(&c->stream, r, "Discarding QMP response with malformed id: %m");
        }
        if (r == 0) {
                qmp_client_clear_current(c);
                json_stream_log(&c->stream, "Discarding unrecognized QMP message");
                return 0;
        }

        _cleanup_free_ QmpPendingCommand *pending = hashmap_remove(c->pending_commands, &(QmpPendingCommand) { .id = id });
        if (!pending)
                /* No async callback registered — leave current pinned for
                 * qmp_client_call() to inspect after process() returns. */
                return 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
        error = qmp_parse_response(v, &result, &desc);

        r = pending->callback(c, result, desc, error, pending->userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");

        return 1;
}

/* Fail all pending async commands with the given error. Called on disconnect. */
static void qmp_client_fail_pending(QmpClient *c, int error) {
        QmpPendingCommand *p;

        assert(c);

        while ((p = hashmap_steal_first(c->pending_commands))) {
                int r = p->callback(c, NULL, NULL, error, p->userdata);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");
                free(p);
        }
}

/* Emit a synthetic SHUTDOWN event when the QMP connection drops unexpectedly. Ensures
 * subscribers learn the VM is gone even if QEMU crashed without sending a SHUTDOWN event
 * (inspired by Incus's synthetic shutdown pattern). */
static void qmp_client_emit_synthetic_shutdown(QmpClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *data = NULL;
        int r;

        assert(c);

        if (!c->event_callback)
                return;

        r = sd_json_buildo(
                        &data,
                        SD_JSON_BUILD_PAIR_BOOLEAN("guest", false),
                        SD_JSON_BUILD_PAIR_STRING("reason", "disconnected"));
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Event callback failed to set data, ignoring: %m");

        r = c->event_callback(c, "SHUTDOWN", data, c->userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Event callback returned error, ignoring: %m");
}

static int qmp_client_handle_disconnect(QmpClient *c) {
        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return 0;

        c->state = QMP_CLIENT_DISCONNECTED;

        /* Disable defer event source so we don't busy-loop on the EOF condition. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_OFF);

        qmp_client_fail_pending(c, -ECONNRESET);
        qmp_client_emit_synthetic_shutdown(c);
        if (c->disconnect_callback)
                c->disconnect_callback(c, c->userdata);

        return 1;
}

static int qmp_client_test_disconnect(QmpClient *c) {
        assert(c);

        /* Already disconnected? */
        if (c->state == QMP_CLIENT_DISCONNECTED)
                return 0;

        if (!json_stream_should_disconnect(&c->stream))
                return 0;

        return qmp_client_handle_disconnect(c);
}

/* Handle handshake progression through sub-states:
 * HANDSHAKE_INITIAL -> receive greeting -> HANDSHAKE_GREETING_RECEIVED
 * HANDSHAKE_GREETING_RECEIVED -> send qmp_capabilities -> HANDSHAKE_CAPABILITIES_SENT
 * HANDSHAKE_CAPABILITIES_SENT -> receive response -> RUNNING */
static int qmp_client_dispatch_handshake(QmpClient *c) {
        int r;

        assert(c);
        assert(QMP_CLIENT_STATE_IS_HANDSHAKE(c->state));

        if (!c->current)
                return 0;

        switch (c->state) {

        case QMP_CLIENT_HANDSHAKE_INITIAL: {
                /* Waiting for QMP greeting */
                sd_json_variant *result = sd_json_variant_by_key(c->current, "QMP");
                qmp_client_clear_current(c);
                if (!result) {
                        json_stream_log(&c->stream, "Expected QMP greeting, got something else");
                        return -EPROTO;
                }

                c->state = QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED;

                /* Fall through to immediately send capabilities */
                _fallthrough_;
        }

        case QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED: {
                /* Send qmp_capabilities command */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
                r = sd_json_buildo(
                                &cmd,
                                SD_JSON_BUILD_PAIR_STRING("execute", "qmp_capabilities"),
                                SD_JSON_BUILD_PAIR_UNSIGNED("id", c->next_id++));
                if (r < 0)
                        return r;

                r = json_stream_enqueue(&c->stream, cmd);
                if (r < 0)
                        return r;

                c->state = QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT;
                return 1;
        }

        case QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT: {
                /* Waiting for qmp_capabilities response */
                const char *desc = NULL;
                r = qmp_parse_response(c->current, /* ret_result= */ NULL, &desc);
                qmp_client_clear_current(c);
                if (r < 0) {
                        json_stream_log(&c->stream, "qmp_capabilities failed: %s", desc);
                        return -EPROTO;
                }

                c->state = QMP_CLIENT_RUNNING;
                return 1;
        }

        default:
                assert_not_reached();
        }
}

static int qmp_client_dispatch(QmpClient *c) {
        assert(c);

        if (!c->current)
                return 0;

        if (QMP_CLIENT_STATE_IS_HANDSHAKE(c->state))
                return qmp_client_dispatch_handshake(c);

        return qmp_client_dispatch_reply(c);
}

/* Perform a single step of QMP processing. Returns 1 if progress was made, 0 if nothing
 * is available (caller should wait), negative on error. Matches sd-varlink's
 * sd_varlink_process() pattern. Step chain: write -> dispatch -> parse -> read -> disconnect.
 * When attached to an event loop, enables the defer event source on progress so
 * processing continues on the next event loop iteration. */
static int qmp_client_process(QmpClient *c) {
        int r;

        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED || c->state == _QMP_CLIENT_STATE_INVALID)
                return -ENOTCONN;

        /* Take a temporary ref to prevent destruction mid-callback, matching
         * sd_varlink_process()'s pattern. A callback invoked during dispatch might
         * drop the last external ref, which would otherwise free us mid-execution. */
        qmp_client_ref(c);

        /* 1. Write — drain output buffer */
        r = json_stream_write(&c->stream);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Write failed: %m");
        if (r != 0)
                goto finish;

        /* 2. Dispatch — route based on state */
        r = qmp_client_dispatch(c);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Dispatch failed: %m");
        if (r != 0)
                goto finish;

        /* 3. Parse — extract one complete message into c->current */
        if (!c->current) {
                r = json_stream_parse(&c->stream, &c->current);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Message parsing failed: %m");
                if (r != 0)
                        goto finish;
        }

        /* 4. Read — fill input buffer from fd */
        if (!c->current) {
                r = json_stream_read(&c->stream);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Read failed: %m");
                if (r != 0)
                        goto finish;
        }

        /* 5. Test disconnect */
        r = qmp_client_test_disconnect(c);
        assert(r >= 0);
        if (r != 0)
                goto finish;

finish:
        /* If progress was made and we have a defer source, enable it so we get called again
         * on the next event loop iteration — matching sd-varlink's pattern. */
        if (r >= 0 && c->defer_event_source) {
                int q;

                q = sd_event_source_set_enabled(c->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0)
                        r = json_stream_log_errno(&c->stream, q, "Failed to enable deferred event source: %m");
        }

        if (r < 0 && c->state != QMP_CLIENT_DISCONNECTED)
                /* On error, initiate disconnection — matching sd_varlink_process()'s
                 * transition to VARLINK_PENDING_DISCONNECT on failure. */
                qmp_client_handle_disconnect(c);

        qmp_client_unref(c);
        return r;
}

/* Map the QMP client state machine onto the generic transport-level "phase". The transport
 * uses this to decide whether to ask for POLLIN, whether the connection is salvageable
 * after a read/write disconnect, and whether the idle timeout deadline is in force. */
static JsonStreamPhase qmp_client_phase(void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        /* During handshake we're waiting for the greeting or qmp_capabilities response. */
        if (QMP_CLIENT_STATE_IS_HANDSHAKE(c->state) && !c->current)
                return JSON_STREAM_PHASE_AWAITING_REPLY;

        /* Running with pending async commands — waiting for their responses. */
        if (c->state == QMP_CLIENT_RUNNING && !c->current &&
            !hashmap_isempty(c->pending_commands))
                return JSON_STREAM_PHASE_AWAITING_REPLY;

        /* Running with no pending commands — waiting for unsolicited events. */
        if (c->state == QMP_CLIENT_RUNNING && !c->current)
                return JSON_STREAM_PHASE_READING;

        return JSON_STREAM_PHASE_OTHER;
}

static int qmp_client_dispatch_cb(void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);
        return qmp_client_process(c);
}

static int qmp_client_defer_callback(sd_event_source *source, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        assert(source);

        (void) qmp_client_process(c);

        return 1;
}

/* Drive the handshake to completion if it hasn't finished yet. Matching
 * sd-bus's bus_ensure_running(). Returns 1 when RUNNING, negative errno
 * on failure. */
static int qmp_client_ensure_running(QmpClient *c) {
        int r;

        assert(c);

        if (c->state == QMP_CLIENT_RUNNING)
                return 1;

        for (;;) {
                if (IN_SET(c->state, QMP_CLIENT_DISCONNECTED, _QMP_CLIENT_STATE_INVALID))
                        return -ENOTCONN;

                r = qmp_client_process(c);
                if (r < 0)
                        return r;
                if (c->state == QMP_CLIENT_RUNNING)
                        return 1;
                if (r > 0)
                        continue;

                r = json_stream_wait(&c->stream, USEC_INFINITY);
                if (r < 0)
                        return r;
        }
}

static void qmp_client_detach_event(QmpClient *c) {
        if (!c)
                return;

        c->defer_event_source = sd_event_source_disable_unref(c->defer_event_source);
        c->quit_event_source = sd_event_source_disable_unref(c->quit_event_source);
        json_stream_detach_event(&c->stream);
}

static void qmp_client_clear(QmpClient *c) {
        assert(c);

        qmp_client_handle_disconnect(c);
        qmp_client_detach_event(c);
        qmp_client_clear_current(c);
        json_stream_done(&c->stream);
        c->pending_commands = hashmap_free(c->pending_commands);
}

/* Drain all pending output. Blocks until the output buffer is empty, matching
 * sd_varlink_flush(). */
static int qmp_client_flush(QmpClient *c) {
        if (!c)
                return 0;

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        return json_stream_flush(&c->stream);
}

/* Close the QMP connection: notify pending callbacks, fire disconnect callback,
 * detach event sources, close the fd. The object stays alive until the last
 * unref. Matches sd_varlink_close(). */
static int qmp_client_close(QmpClient *c) {
        if (!c)
                return 0;

        /* Take a temporary ref to prevent destruction mid-callback,
         * matching sd_varlink_close()'s pattern. */
        qmp_client_ref(c);
        qmp_client_clear(c);
        qmp_client_unref(c);

        return 1;
}

static int qmp_client_quit_callback(sd_event_source *source, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        assert(source);

        qmp_client_flush(c);
        qmp_client_close(c);

        return 1;
}

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. The fd is switched
 * to non-blocking by json_stream_connect_fd_pair(). The handshake (greeting + qmp_capabilities)
 * runs through the process()+wait() loop using the HANDSHAKING state. Call
 * qmp_client_attach_event() afterwards for async operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd) {
        _cleanup_(qmp_client_unrefp) QmpClient *c = NULL;
        _cleanup_close_ int fd_copy = fd;
        int r;

        assert(ret);
        assert(fd >= 0);

        c = new(QmpClient, 1);
        if (!c)
                return -ENOMEM;

        *c = (QmpClient) {
                .n_ref = 1,
                .state = QMP_CLIENT_HANDSHAKE_INITIAL,
                .next_id = 1,
        };

        const JsonStreamParams params = {
                /* QMP framing on the wire is `\r\n` (QEMU's monitor_puts_locked converts
                 * `\n` to `\r\n`), but we split on `\n` and let JSON parsing absorb the
                 * trailing `\r` as insignificant whitespace. */
                .delimiter = "\n",
                .phase = qmp_client_phase,
                .dispatch = qmp_client_dispatch_cb,
                .userdata = c,
        };

        r = json_stream_init(&c->stream, &params);
        if (r < 0)
                return r;

        r = json_stream_connect_fd_pair(&c->stream, fd, fd);
        if (r < 0)
                return r;

        TAKE_FD(fd_copy); /* stream owns the fd now */
        *ret = TAKE_PTR(c);
        return 0;
}

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority) {
        int r;

        assert(c);
        assert(event);
        assert(!json_stream_get_event(&c->stream));

        r = json_stream_attach_event(&c->stream, event, priority);
        if (r < 0)
                return r;

        sd_event *ev = json_stream_get_event(&c->stream);

        r = sd_event_add_exit(ev, &c->quit_event_source, qmp_client_quit_callback, c);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(c->quit_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(c->quit_event_source, "qmp-client-quit");

        r = sd_event_add_defer(ev, &c->defer_event_source, qmp_client_defer_callback, c);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(c->defer_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_OFF);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(c->defer_event_source, "qmp-client-defer");

        return 0;

fail:
        qmp_client_detach_event(c);
        return r;
}

/* Send a synchronous QMP command and wait for the response (process+wait loop).
 * Matches sd_bus_call(): drives the handshake to completion transparently, then
 * loops process()+wait() checking for the reply by id — without changing state.
 * Returns borrowed references into the pinned c->current (valid until next
 * call/close). Returns 1 on success, -EIO on QMP error when ret_error_desc is
 * NULL, negative errno on transport failure. */
int qmp_client_call(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                const char **ret_error_desc) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        uint64_t call_id;
        int r;

        assert(c);
        assert(command);

        r = qmp_client_ensure_running(c);
        if (r < 0)
                return r;

        /* Clear any pinned response from a previous call */
        qmp_client_clear_current(c);

        r = qmp_client_build_command(c, command, arguments, &cmd, &call_id);
        if (r < 0)
                return r;

        r = json_stream_enqueue(&c->stream, cmd);
        if (r < 0)
                return r;

        for (;;) {
                r = qmp_client_process(c);
                if (r < 0)
                        return r;

                if (c->state == QMP_CLIENT_DISCONNECTED)
                        return -ECONNRESET;

                /* After process(), check if dispatch_reply() left our response
                 * pinned in c->current (no async callback matched it). */
                if (c->current) {
                        sd_json_variant *result = NULL;
                        const char *desc = NULL;
                        uint64_t resp_id;
                        int id_r;

                        id_r = qmp_extract_response_id(c->current, &resp_id);
                        if (id_r <= 0 || resp_id != call_id) {
                                /* Not our reply (or malformed id) — clear and continue */
                                qmp_client_clear_current(c);
                                continue;
                        }

                        r = qmp_parse_response(c->current, &result, &desc);
                        if (r < 0 && !ret_error_desc)
                                return r;

                        /* Got our reply — leave current pinned so the
                         * caller gets borrowed references. */
                        if (ret_result)
                                *ret_result = result;
                        if (ret_error_desc)
                                *ret_error_desc = desc;

                        return 1;
                }

                if (r > 0)
                        continue;

                r = json_stream_wait(&c->stream, USEC_INFINITY);
                if (r < 0)
                        return r;
        }
}

int qmp_client_invoke(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_free_ QmpPendingCommand *pending = NULL;
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(callback);

        r = qmp_client_ensure_running(c);
        if (r < 0)
                return r;

        /* Clear any pinned response from a previous call() so it doesn't
         * block the I/O pipeline (get_events checks !c->current for EPOLLIN). */
        qmp_client_clear_current(c);

        r = qmp_client_build_command(c, command, arguments, &cmd, &id);
        if (r < 0)
                return r;

        pending = new(QmpPendingCommand, 1);
        if (!pending)
                return -ENOMEM;

        *pending = (QmpPendingCommand) {
                .id       = id,
                .callback = callback,
                .userdata = userdata,
        };

        r = hashmap_ensure_put(&c->pending_commands, &qmp_pending_command_hash_ops, pending, pending);
        if (r < 0)
                return r;

        r = json_stream_enqueue(&c->stream, cmd);
        if (r < 0) {
                hashmap_remove(c->pending_commands, pending);
                return r;
        }

        /* Enable defer source so process() runs on next event loop iteration to
         * drain the output buffer. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_ON);

        TAKE_PTR(pending);
        return 0;
}

int qmp_client_push_fd(QmpClient *c, int fd) {
        assert(c);
        assert(fd >= 0);

        return json_stream_push_fd(&c->stream, fd);
}

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback) {
        assert(c);
        c->event_callback = callback;
}

void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback) {
        assert(c);
        c->disconnect_callback = callback;
}

void *qmp_client_set_userdata(QmpClient *c, void *userdata) {
        void *old;

        assert(c);

        old = c->userdata;
        c->userdata = userdata;
        return old;
}

int qmp_client_set_description(QmpClient *c, const char *description) {
        assert(c);
        return json_stream_set_description(&c->stream, description);
}

sd_event *qmp_client_get_event(QmpClient *c) {
        if (c)
                return json_stream_get_event(&c->stream);

        return NULL;
}

unsigned qmp_client_next_fdset_id(QmpClient *c) {
        assert(c);
        return c->next_fdset_id++;
}
