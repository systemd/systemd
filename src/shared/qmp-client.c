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
        QMP_CLIENT_RUNNING,                     /* connection alive; qmp_capabilities may still be in flight */
        QMP_CLIENT_DISCONNECTED,                /* connection closed */
        _QMP_CLIENT_STATE_MAX,
        _QMP_CLIENT_STATE_INVALID = -EINVAL,
} QmpClientState;

struct QmpSlot {
        unsigned n_ref;
        QmpClient *client;  /* NULL once disconnected (reply dispatched, cancelled, or client died) */
        uint64_t id;
        bool floating;
        qmp_command_callback_t callback;
        void *userdata;
};

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

        uint64_t next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

        QmpClientState state;
        sd_json_variant *current;  /* most recently parsed message, pending dispatch */

        void *userdata;
};

static void qmp_slot_hash_func(const QmpSlot *p, struct siphash *state) {
        siphash24_compress_typesafe(p->id, state);
}

static int qmp_slot_compare_func(const QmpSlot *a, const QmpSlot *b) {
        return CMP(a->id, b->id);
}

DEFINE_PRIVATE_HASH_OPS(qmp_slot_hash_ops,
                        QmpSlot, qmp_slot_hash_func, qmp_slot_compare_func);

/* Break the slot's connection to the client: remove from the lookup set, drop whichever reference
 * is implied by the slot's floating-ness. For floating slots, the set is the sole owner, so with
 * unref=true we also drop the slot's n_ref (usually dropping it to zero and freeing). For
 * non-floating slots, we release the back-reference the slot holds on the client.
 *
 * Safe to call multiple times: once slot->client is NULL, subsequent calls are no-ops. */
static void qmp_slot_disconnect(QmpSlot *slot, bool unref) {
        assert(slot);

        if (!slot->client)
                return;

        QmpClient *client = slot->client;

        set_remove(client->slots, slot);
        slot->client = NULL;

        if (!slot->floating)
                qmp_client_unref(client);
        else if (unref)
                /* May re-enter via qmp_slot_free→qmp_slot_disconnect(,false) if this drops the
                 * last ref, but the early return above makes that recursion a no-op. */
                qmp_slot_unref(slot);
}

static QmpSlot* qmp_slot_free(QmpSlot *slot) {
        if (!slot)
                return NULL;

        /* Idempotent: if the slot was already disconnected (reply dispatched, explicit cancel,
         * or client-side teardown), this is a no-op. Otherwise it removes us from the set and
         * drops our client reference (for non-floating slots). */
        qmp_slot_disconnect(slot, /* unref= */ false);

        return mfree(slot);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(QmpSlot, qmp_slot, qmp_slot_free);

QmpClient* qmp_slot_get_client(QmpSlot *slot) {
        assert(slot);
        return slot->client;
}

static int qmp_slot_new(
                QmpClient *client,
                bool floating,
                uint64_t id,
                qmp_command_callback_t callback,
                void *userdata,
                QmpSlot **ret) {

        int r;

        assert(client);
        assert(ret);

        _cleanup_(qmp_slot_unrefp) QmpSlot *slot = new(QmpSlot, 1);
        if (!slot)
                return -ENOMEM;

        *slot = (QmpSlot) {
                .n_ref    = 1,
                .client   = NULL,   /* wired up below, after set_put succeeds */
                .id       = id,
                .floating = floating,
                .callback = callback,
                .userdata = userdata,
        };

        r = set_ensure_put(&client->slots, &qmp_slot_hash_ops, slot);
        if (r < 0)
                return r;
        assert(r > 0);

        slot->client = client;
        if (!floating)
                qmp_client_ref(client);

        *ret = TAKE_PTR(slot);
        return 0;
}

static void qmp_client_clear(QmpClient *c);

static QmpClient* qmp_client_free(QmpClient *c) {
        if (!c)
                return NULL;

        qmp_client_clear(c);

        return mfree(c);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(QmpClient, qmp_client, qmp_client_free);

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
static int qmp_client_dispatch(QmpClient *c) {
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

        /* QEMU sends a one-shot greeting with a "QMP" key unsolicited on connect. We don't
         * wait for it before sending qmp_capabilities (QEMU accepts commands the moment the
         * socket is open), we detect it by the "QMP" key and drop it. */
        if (sd_json_variant_by_key(c->current, "QMP")) {
                qmp_client_clear_current(c);
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

        QmpSlot *slot = set_get(c->slots, &(QmpSlot) { .id = id });
        if (!slot) {
                qmp_client_clear_current(c);
                json_stream_log(&c->stream, "Discarding QMP response with unknown id %" PRIu64, id);
                return 1;
        }

        /* Synchronous slot (no callback): leave c->current pinned so qmp_client_call() can
         * pick up the reply and hand out borrowed pointers into it. The sync caller owns a
         * ref on the slot and detects completion by observing slot->client turning NULL. */
        if (!slot->callback) {
                qmp_slot_disconnect(slot, /* unref= */ true);
                return 1;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
        error = qmp_parse_response(v, &result, &desc);

        /* Pin the slot across the callback regardless of floating-ness. For a floating slot,
         * disconnect(unref=true) drops the set's implicit ref which would otherwise free it
         * out from under the callback. */
        qmp_slot_ref(slot);

        r = slot->callback(c, result, desc, error, slot->userdata);
        if (r < 0)
                json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");

        qmp_slot_disconnect(slot, /* unref= */ true);
        qmp_slot_unref(slot);

        return 1;
}

/* Fail all pending commands with the given error. Called on disconnect. */
static void qmp_client_fail_pending(QmpClient *c, int error) {
        QmpSlot *slot;
        int r;

        assert(c);

        while ((slot = set_first(c->slots))) {
                /* Keep alive across the callback and past disconnect (which may unref it for
                 * floating slots). */
                qmp_slot_ref(slot);

                if (slot->callback) {
                        r = slot->callback(c, /* result= */ NULL, /* error_desc= */ NULL, error, slot->userdata);
                        if (r < 0)
                                json_stream_log_errno(&c->stream, r, "Command callback returned error, ignoring: %m");
                }

                qmp_slot_disconnect(slot, /* unref= */ true);
                qmp_slot_unref(slot);
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

        /* 2. Dispatch — dispatch incoming messages to slots */
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

void* qmp_client_set_userdata(QmpClient *c, void *userdata) {
        void *old;

        assert(c);

        old = c->userdata;
        c->userdata = userdata;
        return old;
}

void* qmp_client_get_userdata(QmpClient *c) {
        assert(c);
        return c->userdata;
}

/* Map our state to the transport phase used for POLLIN / salvage / timeout decisions. */
static JsonStreamPhase qmp_client_phase(void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        /* A parsed-but-undispatched message is mid-processing, not waiting on the wire. */
        if (c->current)
                return JSON_STREAM_PHASE_OTHER;

        if (c->state != QMP_CLIENT_RUNNING)
                return JSON_STREAM_PHASE_OTHER;

        /* Pending slots (user commands or the initial qmp_capabilities) → awaiting reply.
         * Otherwise we're idling for unsolicited events. */
        return set_isempty(c->slots)
                        ? JSON_STREAM_PHASE_READING
                        : JSON_STREAM_PHASE_AWAITING_REPLY;
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

static int qmp_client_send(
                QmpClient *c,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata,
                QmpSlot **ret_slot);

/* Reply callback for the eagerly-enqueued qmp_capabilities command. Success → we stay in
 * RUNNING. Failure → negotiation is unrecoverable, force-disconnect so the next user op gets
 * -ENOTCONN rather than hanging. */
static int qmp_client_capabilities_reply(
                QmpClient *c,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        /* qmp_client_handle_disconnect() below fails all pending slots, which re-enters this
         * callback with -ECONNRESET on our own still-registered slot. Short-circuit that. */
        if (c->state == QMP_CLIENT_DISCONNECTED)
                return 0;

        if (error >= 0)
                return 0;

        json_stream_log_errno(&c->stream, error, "qmp_capabilities failed: %s", strna(error_desc));
        qmp_client_handle_disconnect(c);
        return 0;
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
                .state = QMP_CLIENT_RUNNING,
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

        /* Eagerly queue qmp_capabilities. QEMU accepts commands as soon as the socket opens
         * — its greeting is informational and doesn't gate writes on our side. FIFO ordering
         * of the output queue guarantees cap precedes any user command a later invoke()
         * enqueues, which is all QEMU actually requires. */
        r = qmp_client_send(c, "qmp_capabilities", /* args= */ NULL,
                            qmp_client_capabilities_reply, /* userdata= */ NULL,
                            /* ret_slot= */ NULL);
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

/* Shared send path for qmp_client_invoke() and qmp_client_call(). A NULL callback registers
 * a "synchronous" slot: dispatch_reply leaves c->current pinned on match instead of invoking
 * a callback, so qmp_client_call() can hand out borrowed pointers into the reply. If ret_slot
 * is NULL the slot is allocated as floating (owned by c->slots); otherwise a reference is
 * handed back to the caller. */
static int qmp_client_send(
                QmpClient *c,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata,
                QmpSlot **ret_slot) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_(qmp_slot_unrefp) QmpSlot *slot = NULL;
        /* Closes any fds in args on every early-return path; TAKE_PTR()'d on the success path
         * below once json_stream_enqueue_full() has taken ownership of them. */
        _cleanup_(qmp_client_args_close_fdsp) QmpClientArgs *fds_owner = args;
        uint64_t id;
        int r;

        assert(c);
        assert(command);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        r = qmp_client_build_command(c, command, args ? args->arguments : NULL, &cmd, &id);
        if (r < 0)
                return r;

        r = qmp_slot_new(c, /* floating= */ !ret_slot, id, callback, userdata, &slot);
        if (r < 0)
                return r;

        r = json_stream_enqueue_full(&c->stream, cmd,
                                     args ? args->fds_consume : NULL,
                                     args ? args->n_fds : 0);
        if (r < 0)
                return r;  /* slot cleanup disconnects it */

        /* Arm defer so process() drains the output on the next iteration. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_ON);

        TAKE_PTR(fds_owner);

        if (ret_slot)
                *ret_slot = TAKE_PTR(slot);
        else
                TAKE_PTR(slot);  /* floating: c->slots keeps it alive until dispatch */

        return 0;
}

int qmp_client_invoke(
                QmpClient *c,
                QmpSlot **ret_slot,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata) {

        assert(callback);
        return qmp_client_send(c, command, args, callback, userdata, ret_slot);
}

int qmp_client_call(
                QmpClient *c,
                const char *command,
                QmpClientArgs *args,
                sd_json_variant **ret_result,
                const char **ret_error_desc) {

        _cleanup_(qmp_slot_unrefp) QmpSlot *slot = NULL;
        int r;

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);

        /* Drop any reply pinned by a previous qmp_client_call() before we pin a new one. */
        qmp_client_clear_current(c);

        /* NULL callback marks this as a synchronous slot: dispatch_reply matches on id like
         * any other slot (so stray unknown-id replies still get logged and dropped), but
         * pins c->current for us instead of invoking a callback. The slot is non-floating so
         * we can observe dispatch by watching slot->client go NULL. */
        r = qmp_client_send(c, command, args, /* callback= */ NULL, /* userdata= */ NULL, &slot);
        if (r < 0)
                return r;

        /* Pump the loop until our sync slot fires (disconnected by dispatch, c->current pinned). */
        for (;;) {
                if (c->state == QMP_CLIENT_DISCONNECTED)
                        return -ECONNRESET;

                if (!slot->client) {
                        assert(c->current);
                        break;
                }

                r = qmp_client_process(c);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = qmp_client_wait(c, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        sd_json_variant *result = NULL;
        const char *desc = NULL;
        int error = qmp_parse_response(c->current, &result, &desc);

        /* If caller doesn't ask for the error string, surface the error as the return code. */
        if (!ret_error_desc && error < 0)
                return error;

        if (ret_result)
                *ret_result = result;
        if (ret_error_desc)
                *ret_error_desc = desc;

        return 1;
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

uint64_t qmp_client_next_fdset_id(QmpClient *c) {
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
