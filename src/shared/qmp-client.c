/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hash-funcs.h"
#include "json-stream.h"
#include "json-util.h"
#include "qmp-client.h"
#include "set.h"
#include "siphash24.h"
#include "string-util.h"

typedef enum QmpClientState {
        QMP_CLIENT_HANDSHAKE_INITIAL,           /* waiting for QMP greeting */
        QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED, /* greeting received, sending qmp_capabilities */
        QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT, /* waiting for qmp_capabilities response */
        QMP_CLIENT_RUNNING,                     /* connected, ready for commands */
        QMP_CLIENT_DISCONNECTED,                /* connection closed */
        _QMP_CLIENT_STATE_MAX,
        _QMP_CLIENT_STATE_INVALID = -EINVAL,
} QmpClientState;

/* States routed to dispatch_handshake. */
#define QMP_CLIENT_STATE_IS_HANDSHAKE(s)               \
        IN_SET(s,                                      \
               QMP_CLIENT_HANDSHAKE_INITIAL,           \
               QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED, \
               QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT)

typedef struct QmpSlot {
        uint64_t id;
        qmp_command_callback_t callback;
        void *userdata;
} QmpSlot;

struct QmpClient {
        unsigned n_ref;

        JsonStream stream;

        sd_event_source *quit_event_source;
        sd_event_source *defer_event_source;

        uint64_t next_id;
        Set *slots;     /* QmpSlot* entries indexed by id, for async dispatch */

        qmp_event_callback_t event_callback;
        void *event_userdata;
        qmp_disconnect_callback_t disconnect_callback;
        void *disconnect_userdata;

        unsigned next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

        QmpClientState state;
        sd_json_variant *current;  /* most recently parsed message, pending dispatch */
};

static void qmp_slot_hash_func(const QmpSlot *p, struct siphash *state) {
        siphash24_compress_typesafe(p->id, state);
}

static int qmp_slot_compare_func(const QmpSlot *a, const QmpSlot *b) {
        return CMP(a->id, b->id);
}

DEFINE_PRIVATE_HASH_OPS(qmp_slot_hash_ops,
                        QmpSlot, qmp_slot_hash_func, qmp_slot_compare_func);

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

        r = sd_json_dispatch(v, table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG|SD_JSON_DEBUG, &p);
        if (r < 0)
                return;

        r = c->event_callback(c, p.event, p.data, c->event_userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Event callback returned error, ignoring: %m");
}

/* QEMU's error "class" is effectively always "GenericError"; only "desc" carries useful info. */
static const char* qmp_extract_error_description(sd_json_variant *v) {
        sd_json_variant *error = sd_json_variant_by_key(v, "error");
        if (!error)
                return NULL;
        sd_json_variant *desc = sd_json_variant_by_key(error, "desc");
        if (desc)
                return sd_json_variant_string(desc);
        return "unspecified error";
}

/* Returns 1 with id set; 0 if absent (e.g. pre-parse error responses); -EBADMSG on wrong type. */
static int qmp_extract_response_id(sd_json_variant *v, uint64_t *ret) {
        sd_json_variant *id_variant;

        assert(v);
        assert(ret);

        id_variant = sd_json_variant_by_key(v, "id");
        if (!id_variant) {
                *ret = 0;
                return 0;
        }
        if (!sd_json_variant_is_unsigned(id_variant))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "QMP response 'id' field is not an unsigned integer.");

        *ret = sd_json_variant_unsigned(id_variant);
        return 1;
}

/* Returns 0 on success (ret_result = "return" value), -EIO on QMP error (reterr_desc set). */
static int qmp_parse_response(sd_json_variant *v, sd_json_variant **ret_result, const char **reterr_desc) {
        const char *desc;

        desc = qmp_extract_error_description(v);
        if (desc) {
                if (reterr_desc)
                        *reterr_desc = desc;
                return -EIO;
        }

        if (ret_result)
                *ret_result = sd_json_variant_by_key(v, "return");
        return 0;
}

static int qmp_client_build_command(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret,
                uint64_t *ret_id) {

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

/* Route c->current to event callback or matching async slot. Returns 1 on dispatch. */
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
                return 1;
        }

        _cleanup_free_ QmpSlot *pending = set_remove(c->slots, &(QmpSlot) { .id = id });
        if (!pending) {
                qmp_client_clear_current(c);
                json_stream_log(&c->stream, "Discarding QMP response with unknown id %" PRIu64, id);
                return 1;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
        error = qmp_parse_response(v, &result, &desc);

        r = pending->callback(c, result, desc, error, pending->userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");

        return 1;
}

/* Fail all pending async commands with the given error. Called on disconnect. */
static void qmp_client_fail_pending(QmpClient *c, int error) {
        QmpSlot *p;
        int r;

        assert(c);

        while ((p = set_steal_first(c->slots))) {
                r = p->callback(c, /* result= */ NULL, /* error_desc= */ NULL, error, p->userdata);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");
                free(p);
        }
}

/* Synthetic SHUTDOWN on unexpected disconnect so subscribers learn the VM is gone. */
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
        if (r < 0) {
                json_stream_log_errno(&c->stream, r, "Failed to build synthetic SHUTDOWN event data, skipping: %m");
                return;
        }

        r = c->event_callback(c, "SHUTDOWN", data, c->event_userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Event callback returned error, ignoring: %m");
}

static bool qmp_client_handle_disconnect(QmpClient *c) {
        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return false;

        c->state = QMP_CLIENT_DISCONNECTED;

        /* Disable defer event source so we don't busy-loop on the EOF condition. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_OFF);

        qmp_client_fail_pending(c, -ECONNRESET);
        qmp_client_emit_synthetic_shutdown(c);
        if (c->disconnect_callback)
                c->disconnect_callback(c, c->disconnect_userdata);

        return true;
}

static bool qmp_client_test_disconnect(QmpClient *c) {
        assert(c);

        /* Already disconnected? */
        if (c->state == QMP_CLIENT_DISCONNECTED)
                return false;

        if (!json_stream_should_disconnect(&c->stream))
                return false;

        return qmp_client_handle_disconnect(c);
}

/* INITIAL → greeting → GREETING_RECEIVED → qmp_capabilities → CAPABILITIES_SENT → response → RUNNING. */
static int qmp_client_dispatch_handshake(QmpClient *c) {
        int r;

        assert(c);
        assert(QMP_CLIENT_STATE_IS_HANDSHAKE(c->state));

        if (!c->current)
                return 0;

        /* Defensive: QEMU shouldn't emit events during capability negotiation, but if one
         * arrives, dispatch it as an event rather than mis-parsing it as a handshake reply. */
        if (sd_json_variant_by_key(c->current, "event")) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                qmp_client_dispatch_event(c, v);
                return 1;
        }

        switch (c->state) {

        case QMP_CLIENT_HANDSHAKE_INITIAL: {
                /* Waiting for QMP greeting. Take ownership so by_key()'s borrowed pointer
                 * stays valid through the case scope. */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                if (!sd_json_variant_by_key(v, "QMP"))
                        return json_stream_log_errno(&c->stream, SYNTHETIC_ERRNO(EPROTO),
                                                     "Expected QMP greeting, got something else");

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
                /* Take ownership so desc (borrowed from v's "error.desc") survives the format string. */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                const char *desc = NULL;
                r = qmp_parse_response(v, /* ret_result= */ NULL, &desc);
                if (r < 0)
                        return json_stream_log_errno(&c->stream, SYNTHETIC_ERRNO(EPROTO),
                                                     "qmp_capabilities failed: %s", desc);

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

/* Single step: write → dispatch → parse → read → disconnect. Matches sd_varlink_process(). */
int qmp_client_process(QmpClient *c) {
        int r;

        assert(c);

        if (c->state < 0 || c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        /* Pin against a callback dropping the last ref mid-dispatch. Matches sd_varlink_process(). */
        qmp_client_ref(c);

        /* 1. Write — drain output buffer */
        r = json_stream_write(&c->stream);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Failed to write to QMP socket: %m");
        if (r != 0)
                goto finish;

        /* 2. Dispatch — route based on state */
        r = qmp_client_dispatch(c);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Failed to dispatch QMP message: %m");
        if (r != 0)
                goto finish;

        /* 3. Parse — extract one complete message into c->current */
        if (!c->current) {
                r = json_stream_parse(&c->stream, &c->current);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Failed to parse QMP message: %m");
                if (r != 0)
                        goto finish;
        }

        /* 4. Read — fill input buffer from fd */
        if (!c->current) {
                r = json_stream_read(&c->stream);
                if (r < 0)
                        json_stream_log_errno(&c->stream, r, "Failed to read from QMP socket: %m");
                if (r != 0)
                        goto finish;
        }

        /* 5. Test disconnect */
        if (qmp_client_test_disconnect(c)) {
                r = 1;
                goto finish;
        }

finish:
        /* Re-arm defer source on progress so we get called again next iteration. */
        if (r >= 0 && c->defer_event_source) {
                int q;

                q = sd_event_source_set_enabled(c->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0)
                        r = json_stream_log_errno(&c->stream, q, "Failed to enable deferred event source: %m");
        }

        /* -ENOBUFS is the buffered stream's 16 MiB cap, not a transport error — propagate without disconnecting. */
        if (r < 0 && r != -ENOBUFS && c->state != QMP_CLIENT_DISCONNECTED)
                qmp_client_handle_disconnect(c);

        qmp_client_unref(c);
        return r;
}

int qmp_client_wait(QmpClient *c, uint64_t timeout_usec) {
        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        return json_stream_wait(&c->stream, timeout_usec);
}

bool qmp_client_is_idle(QmpClient *c) {
        assert(c);
        return set_isempty(c->slots);
}

bool qmp_client_is_disconnected(QmpClient *c) {
        assert(c);
        return c->state == QMP_CLIENT_DISCONNECTED;
}

/* Map our state to the transport phase used for POLLIN / salvage / timeout decisions. */
static JsonStreamPhase qmp_client_phase(void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        /* A parsed-but-undispatched message is mid-processing, not waiting on the wire. */
        if (c->current)
                return JSON_STREAM_PHASE_OTHER;

        /* During handshake we're waiting for the greeting or qmp_capabilities response. */
        if (QMP_CLIENT_STATE_IS_HANDSHAKE(c->state))
                return JSON_STREAM_PHASE_AWAITING_REPLY;

        /* Running with pending async commands — waiting for their responses. */
        if (c->state == QMP_CLIENT_RUNNING && !set_isempty(c->slots))
                return JSON_STREAM_PHASE_AWAITING_REPLY;

        /* Running with no pending commands — waiting for unsolicited events. */
        if (c->state == QMP_CLIENT_RUNNING)
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

/* Drive handshake to completion. Matches sd-bus's bus_ensure_running(). */
static int qmp_client_ensure_running(QmpClient *c) {
        int r;

        assert(c);

        if (c->state == QMP_CLIENT_RUNNING)
                return 1;

        for (;;) {
                if (c->state < 0 || c->state == QMP_CLIENT_DISCONNECTED)
                        return -ENOTCONN;

                r = qmp_client_process(c);
                if (r < 0)
                        return r;
                if (c->state == QMP_CLIENT_RUNNING)
                        return 1;
                if (r > 0)
                        continue;

                r = qmp_client_wait(c, USEC_INFINITY);
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
        c->slots = set_free(c->slots);
}

/* Blocks until output buffer is empty. Matches sd_varlink_flush(). */
static int qmp_client_flush(QmpClient *c) {
        if (!c)
                return 0;

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        return json_stream_flush(&c->stream);
}

/* Notify callbacks, fire disconnect, detach sources, close fd. Matches sd_varlink_close(). */
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

int qmp_client_connect_fd(QmpClient **ret, int fd) {
        _cleanup_(qmp_client_unrefp) QmpClient *c = NULL;
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
                .delimiter = "\r\n",
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

/* Cleanup hook: closes any fds in *args not yet transferred to the stream. */
static QmpClientArgs* qmp_client_args_close_fds(QmpClientArgs *p) {
        assert(p);
        close_many_unset(p->fds_consume, p->n_fds);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClientArgs*, qmp_client_args_close_fds);

/* Transfer fds to the stream. On partial failure narrow args to the unstaged tail so
 * the caller's cleanup closes only the untransferred fds. */
static int qmp_client_stage_fds(QmpClient *c, QmpClientArgs *args) {
        int r;

        assert(c);

        if (!args || args->n_fds == 0)
                return 0;

        assert(args->fds_consume);

        for (size_t i = 0; i < args->n_fds; i++) {
                r = json_stream_push_fd(&c->stream, args->fds_consume[i]);
                if (r < 0) {
                        /* Already-staged are owned by the stream; narrow args to the rest. */
                        json_stream_reset_pushed_fds(&c->stream);
                        args->fds_consume = &args->fds_consume[i];
                        args->n_fds -= i;
                        return r;
                }
        }

        args->n_fds = 0;
        return 0;
}

int qmp_client_invoke(
                QmpClient *c,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_free_ QmpSlot *pending = NULL;
        /* Closes any fds in args not yet handed to the stream on every early-return path;
         * TAKE_PTR()'d on the success path below once stage_fds has consumed them. */
        _cleanup_(qmp_client_args_close_fdsp) QmpClientArgs *fds_owner = args;
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(callback);

        r = qmp_client_ensure_running(c);
        if (r < 0)
                return r;

        r = qmp_client_build_command(c, command, args ? args->arguments : NULL, &cmd, &id);
        if (r < 0)
                return r;

        pending = new(QmpSlot, 1);
        if (!pending)
                return -ENOMEM;

        *pending = (QmpSlot) {
                .id       = id,
                .callback = callback,
                .userdata = userdata,
        };

        r = set_ensure_put(&c->slots, &qmp_slot_hash_ops, pending);
        if (r < 0)
                return r;
        assert(r > 0);

        /* Stage AFTER ensure_running() drained internal enqueues so the next enqueue is ours. */
        r = qmp_client_stage_fds(c, args);
        if (r < 0) {
                set_remove(c->slots, pending);
                return r;
        }

        r = json_stream_enqueue(&c->stream, cmd);
        if (r < 0) {
                json_stream_reset_pushed_fds(&c->stream);
                set_remove(c->slots, pending);
                return r;
        }

        /* Arm defer so process() drains the output on the next iteration. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_ON);

        TAKE_PTR(pending);
        TAKE_PTR(fds_owner);
        return 0;
}

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback, void *userdata) {
        assert(c);
        c->event_callback = callback;
        c->event_userdata = userdata;
}

void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback, void *userdata) {
        assert(c);
        c->disconnect_callback = callback;
        c->disconnect_userdata = userdata;
}

int qmp_client_set_description(QmpClient *c, const char *description) {
        assert(c);
        return json_stream_set_description(&c->stream, description);
}

sd_event* qmp_client_get_event(QmpClient *c) {
        assert(c);
        return json_stream_get_event(&c->stream);
}

unsigned qmp_client_next_fdset_id(QmpClient *c) {
        assert(c);
        return c->next_fdset_id++;
}

bool qmp_schema_has_member(sd_json_variant *schema, const char *member_name) {
        sd_json_variant *entry;

        assert(member_name);

        if (!sd_json_variant_is_array(schema))
                return false;

        JSON_VARIANT_ARRAY_FOREACH(entry, schema) {
                if (!sd_json_variant_is_object(entry))
                        continue;

                sd_json_variant *meta = sd_json_variant_by_key(entry, "meta-type");
                if (!meta || !streq_ptr(sd_json_variant_string(meta), "object"))
                        continue;

                sd_json_variant *members = sd_json_variant_by_key(entry, "members");
                if (!sd_json_variant_is_array(members))
                        continue;

                sd_json_variant *m;
                JSON_VARIANT_ARRAY_FOREACH(m, members) {
                        if (!sd_json_variant_is_object(m))
                                continue;
                        sd_json_variant *mn = sd_json_variant_by_key(m, "name");
                        if (mn && streq_ptr(sd_json_variant_string(mn), member_name))
                                return true;
                }
        }

        return false;
}
