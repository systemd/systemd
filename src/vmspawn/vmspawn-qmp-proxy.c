/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "json-stream.h"
#include "json-util.h"
#include "list.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"
#include "vmspawn-qmp.h"
#include "vmspawn-qmp-proxy.h"

/* Cap on concurrent AcquireQMP upgrades. Each acquirer owns a 16 MiB output buffer
 * in the worst case (see json_stream buffer_max). Sixteen is plenty for anything
 * real; guards against a rogue or buggy client exhausting memory. */
#define VMSPAWN_QMP_PROXY_MAX 16U

/* Message that QEMU sends when a non-qmp_capabilities command is attempted during
 * capability negotiation. We reproduce it byte-for-byte so QMP clients that match on
 * the description (there shouldn't be any, but belt+braces) keep working. */
#define QMP_CAP_NEGOTIATION_DESC                                               \
        "Expecting capabilities negotiation with 'qmp_capabilities'"

/* Forward-declare the typedef before the struct body so the self-referential
 * LIST_FIELDS(ProxyCmdCtx, ...) inside the struct resolves against the typedef
 * instead of collapsing into an implicit-int declaration. */
typedef struct ProxyCmdCtx ProxyCmdCtx;

/* Per-outstanding-command bookkeeping. Created when the proxy forwards an acquirer's
 * command to the shared QmpClient; freed when the matching response arrives (or when
 * the acquirer dies first, in which case `aq` is NULLed and the slot callback frees
 * this). */
struct ProxyCmdCtx {
        AcquiredQmp *aq;            /* weak; set to NULL on aq teardown */
        sd_json_variant *caller_id; /* owned; NULL iff had_caller_id == false */
        bool had_caller_id;         /* distinguishes "absent" from "null" */
        LIST_FIELDS(ProxyCmdCtx, pending);
};

struct AcquiredQmp {
        VmspawnQmpBridge *bridge;            /* weak; for bridge->acquired list removal */
        JsonStream stream;                   /* delimiter "\r\n" for native QMP */
        sd_event_source *defer_event_source; /* armed after any step that made progress */
        bool caps_negotiated;                /* acquirer has sent qmp_capabilities */
        LIST_HEAD(ProxyCmdCtx, pending);     /* ProxyCmdCtx entries still in flight */
        LIST_FIELDS(AcquiredQmp, acquired);
};

static ProxyCmdCtx* proxy_cmd_ctx_free(ProxyCmdCtx *ctx) {
        if (!ctx)
                return NULL;

        /* If we're being freed while still linked, someone forgot to LIST_REMOVE us;
         * assert instead of silently leaking list state. */
        assert(ctx->aq == NULL);

        sd_json_variant_unref(ctx->caller_id);
        return mfree(ctx);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ProxyCmdCtx*, proxy_cmd_ctx_free);

static AcquiredQmp* acquired_qmp_free(AcquiredQmp *aq) {
        ProxyCmdCtx *ctx;

        if (!aq)
                return NULL;

        /* Orphan every still-outstanding command so the QmpClient's slot callback
         * (which may fire later, up to and including the -ECONNRESET sweep) drops the
         * response instead of trying to write into our freed stream. */
        while ((ctx = aq->pending)) {
                LIST_REMOVE(pending, aq->pending, ctx);
                ctx->aq = NULL;
        }

        if (aq->bridge) {
                LIST_REMOVE(acquired, aq->bridge->acquired, aq);
                assert(aq->bridge->n_acquired > 0);
                aq->bridge->n_acquired--;
        }

        aq->defer_event_source = sd_event_source_disable_unref(aq->defer_event_source);
        json_stream_done(&aq->stream);
        return mfree(aq);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AcquiredQmp*, acquired_qmp_free);

static JsonStreamPhase on_acquired_phase(void *userdata) {
        AcquiredQmp *aq = ASSERT_PTR(userdata);

        /* Any queued output waiting to be written? */
        if (aq->stream.output_buffer_size > aq->stream.output_buffer_index ||
            aq->stream.output_queue)
                return JSON_STREAM_PHASE_PENDING_OUTPUT;

        /* Otherwise we're waiting for the next acquirer-side command (or EOF). */
        return JSON_STREAM_PHASE_READING;
}

/* Rebuild the acquirer's command object with a fresh id, copying every other key
 * verbatim. QMP's id field may be any JSON value on the wire; since the QmpClient
 * uses uint64_t ids internally we force the rewritten object to carry an unsigned
 * integer. */
static int rewrite_command_with_internal_id(
                sd_json_variant *src,
                uint64_t new_id,
                sd_json_variant **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *out = NULL;
        const char *k;
        sd_json_variant *w;
        int r;

        assert(src);
        assert(ret);

        JSON_VARIANT_OBJECT_FOREACH(k, w, src) {
                if (streq(k, "id"))
                        continue;

                r = sd_json_variant_set_fieldb(
                                &out, k,
                                SD_JSON_BUILD_VARIANT(w));
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_set_fieldb(
                        &out, "id",
                        SD_JSON_BUILD_UNSIGNED(new_id));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(out);
        return 0;
}

static int on_proxy_reply(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(proxy_cmd_ctx_freep) ProxyCmdCtx *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;
        AcquiredQmp *aq = ctx->aq;
        int r;

        assert(client);

        /* Acquirer already gone — drop. Unlinking from aq->pending happens in
         * acquired_qmp_free(); we just need to free ourselves. */
        if (!aq)
                return 0;

        LIST_REMOVE(pending, aq->pending, ctx);
        ctx->aq = NULL;

        /* Caller didn't want to be told — honour that. (Matches native QMP: a
         * command without an id gets no response.) */
        if (!ctx->had_caller_id)
                return 0;

        if (error == 0) {
                /* Success: {"return": <result or {}>, "id": <caller id>} */
                r = sd_json_buildo(
                                &response,
                                SD_JSON_BUILD_PAIR_CONDITION(!!result, "return", SD_JSON_BUILD_VARIANT(result)),
                                SD_JSON_BUILD_PAIR_CONDITION(!result, "return", SD_JSON_BUILD_EMPTY_OBJECT),
                                SD_JSON_BUILD_PAIR_VARIANT("id", ctx->caller_id));
                if (r < 0)
                        return log_warning_errno(r, "Failed to build QMP proxy success response, dropping: %m");
        } else {
                /* Error. QEMU's error class is always "GenericError" in practice (see
                 * qmp-error-desc-guarantees.md in the project notes); the existing
                 * qmp_command_callback_t contract drops the original class and keeps
                 * only the desc. Reconstruct with GenericError — QMP spec forbids
                 * clients from parsing class values anyway. Transport errors
                 * (ERRNO_IS_DISCONNECT(error)) are short-lived: the bridge is about
                 * to be torn down and the acquirer sees EOF from the drain path, so
                 * emitting a synthetic error here is courtesy, not contract. */
                const char *desc = error_desc ?: "unspecified error";
                r = sd_json_buildo(
                                &response,
                                SD_JSON_BUILD_PAIR(
                                        "error",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_STRING("class", "GenericError"),
                                                SD_JSON_BUILD_PAIR_STRING("desc", desc))),
                                SD_JSON_BUILD_PAIR_VARIANT("id", ctx->caller_id));
                if (r < 0)
                        return log_warning_errno(r, "Failed to build QMP proxy error response, dropping: %m");
        }

        r = json_stream_enqueue(&aq->stream, response);
        if (r < 0)
                log_warning_errno(r, "Failed to enqueue QMP proxy response to acquirer, dropping: %m");

        return 0;
}

static int acquired_qmp_enqueue_error(
                AcquiredQmp *aq,
                const char *error_class,
                const char *desc,
                sd_json_variant *caller_id,
                bool had_caller_id) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;
        int r;

        assert(aq);
        assert(error_class);
        assert(desc);

        r = sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR(
                                "error",
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("class", error_class),
                                        SD_JSON_BUILD_PAIR_STRING("desc", desc))),
                        SD_JSON_BUILD_PAIR_CONDITION(had_caller_id, "id", SD_JSON_BUILD_VARIANT(caller_id)));
        if (r < 0)
                return r;

        return json_stream_enqueue(&aq->stream, response);
}

static int acquired_qmp_enqueue_empty_return(
                AcquiredQmp *aq,
                sd_json_variant *caller_id,
                bool had_caller_id) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;
        int r;

        assert(aq);

        r = sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_EMPTY_OBJECT),
                        SD_JSON_BUILD_PAIR_CONDITION(had_caller_id, "id", SD_JSON_BUILD_VARIANT(caller_id)));
        if (r < 0)
                return r;

        return json_stream_enqueue(&aq->stream, response);
}

/* Parse one QMP command from the acquirer and dispatch it.
 *
 * Returns 0 on success (including the cases where we replied with an error). Returns
 * a negative errno only if the acquirer should be torn down (e.g. -ENOBUFS from a
 * flooded output buffer, or malformed JSON). */
static int acquired_qmp_parse_one(AcquiredQmp *aq, sd_json_variant *cmd) {
        int r;

        assert(aq);
        assert(cmd);

        /* Distinguish "id absent" from "id present but JSON null". Both are legal QMP;
         * the former means the caller doesn't want a response, the latter carries null
         * back as the correlation value. */
        sd_json_variant *id_variant = sd_json_variant_by_key(cmd, "id");
        bool had_caller_id = id_variant != NULL;
        /* Take an independent ref so the rewritten command we build below can unref
         * the original without affecting ctx->caller_id's lifetime. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *caller_id =
                sd_json_variant_ref(id_variant);

        /* Cap-negotiation gate, mirroring QEMU monitor/qmp.c semantics exactly:
         *
         *   a) execute=="qmp_capabilities" (with or without arguments): short-circuit
         *      locally with an empty return and flip into full command mode. QEMU's
         *      own monitor is already past negotiation (vmspawn did that at startup),
         *      so forwarding would hit CommandNotFound in full mode.
         *
         *   b) execute=="<other>" or exec-oob=="<any>" while still in negotiation
         *      mode: respond with CommandNotFound and the specific desc that QEMU
         *      substitutes in monitor_qmp_dispatcher_co when a caps-mode monitor
         *      rejects a non-qmp_capabilities command.
         *
         *   c) Anything else (no command key, non-string command, unexpected keys,
         *      clashing execute+exec-oob) is a shape error. QEMU emits a very
         *      specific GenericError desc for each of those cases; rather than
         *      reimplement its shape validator, we forward the message unchanged and
         *      let QEMU produce the exact error — its monitor state doesn't matter
         *      for shape validation, so the wire response is identical to what a
         *      fresh QMP session would produce.
         *
         *   d) Post-caps: forward everything (apart from qmp_capabilities, case a).
         */
        sd_json_variant *execute = sd_json_variant_by_key(cmd, "execute");
        sd_json_variant *exec_oob = sd_json_variant_by_key(cmd, "exec-oob");
        bool execute_is_string = execute && sd_json_variant_is_string(execute);

        if (execute_is_string &&
            streq(sd_json_variant_string(execute), "qmp_capabilities")) {
                aq->caps_negotiated = true;
                return acquired_qmp_enqueue_empty_return(aq, caller_id, had_caller_id);
        }

        if (!aq->caps_negotiated &&
            (execute_is_string ||
             (exec_oob && sd_json_variant_is_string(exec_oob))))
                return acquired_qmp_enqueue_error(
                                aq, "CommandNotFound", QMP_CAP_NEGOTIATION_DESC,
                                caller_id, had_caller_id);

        /* Remap id, forward to the shared QmpClient. */
        uint64_t internal_id = qmp_client_reserve_id(aq->bridge->qmp);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *rewritten = NULL;
        r = rewrite_command_with_internal_id(cmd, internal_id, &rewritten);
        if (r < 0)
                return acquired_qmp_enqueue_error(
                                aq, "GenericError",
                                "Failed to rewrite QMP command for forwarding",
                                caller_id, had_caller_id);

        _cleanup_(proxy_cmd_ctx_freep) ProxyCmdCtx *ctx = new(ProxyCmdCtx, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (ProxyCmdCtx) {
                .aq = aq,
                .caller_id = TAKE_PTR(caller_id),
                .had_caller_id = had_caller_id,
        };

        LIST_PREPEND(pending, aq->pending, ctx);

        r = qmp_client_invoke_raw(
                        aq->bridge->qmp, rewritten, internal_id,
                        /* args= */ NULL, on_proxy_reply, ctx);
        if (r < 0) {
                LIST_REMOVE(pending, aq->pending, ctx);
                ctx->aq = NULL; /* satisfy the proxy_cmd_ctx_free() assert */

                if (r == -ENOTCONN)
                        /* Shared QmpClient just died. Acquirer will see EOF shortly
                         * via the bridge's disconnect drain; report a best-effort
                         * error and keep going. */
                        return acquired_qmp_enqueue_error(
                                        aq, "GenericError",
                                        "QMP backend is no longer connected",
                                        ctx->caller_id, ctx->had_caller_id);

                return r;
        }

        /* On successful forward ctx is owned by the QmpClient slot (via its userdata)
         * and will be freed when on_proxy_reply fires. */
        TAKE_PTR(ctx);
        return 0;
}

/* One step per call: write → parse-and-dispatch → read → disconnect-test. Matches
 * qmp_client_process()'s shape and return contract:
 *   > 0 — made progress, caller should re-enable the defer source so we fire again
 *   = 0 — idle, wait for the next I/O event
 *   < 0 — fatal, acquirer torn down
 *
 * Any failure path falls through the cleanup attribute and frees aq; successful
 * paths TAKE_PTR. The defer_event_source is armed/disarmed based on the progress
 * indicator, mirroring how qmp-client and sd-varlink keep draining work that is
 * buffered internally (where level-triggered I/O won't re-fire on its own). */
static int acquired_qmp_process(AcquiredQmp *aq_in) {
        _cleanup_(acquired_qmp_freep) AcquiredQmp *aq = ASSERT_PTR(aq_in);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *msg = NULL;
        int r;

        /* 1. Write — drain output buffer */
        r = json_stream_write(&aq->stream);
        if (r < 0) {
                log_debug_errno(r, "QMP acquirer write failed, disconnecting: %m");
                return r;
        }
        if (r > 0)
                goto finish;

        /* 2. Parse + dispatch — handle one complete inbound message if buffered */
        r = json_stream_parse(&aq->stream, &msg);
        if (r < 0) {
                log_debug_errno(r, "QMP acquirer sent malformed JSON, disconnecting: %m");
                return r;
        }
        if (r > 0) {
                r = acquired_qmp_parse_one(aq, msg);
                if (r < 0) {
                        log_debug_errno(r, "QMP acquirer dispatch failed, disconnecting: %m");
                        return r;
                }
                r = 1; /* parse + dispatch counts as progress */
                goto finish;
        }

        /* 3. Read — fill input buffer from fd */
        r = json_stream_read(&aq->stream);
        if (r < 0) {
                log_debug_errno(r, "QMP acquirer read failed, disconnecting: %m");
                return r;
        }
        if (r > 0)
                goto finish;

        /* 4. Test disconnect */
        if (json_stream_should_disconnect(&aq->stream)) {
                log_debug("QMP acquirer disconnected (peer closed)");
                return -ECONNRESET;
        }

finish:
        /* Arm the defer source if progress was made so the next event loop iteration
         * calls us again to drain whatever follows. Disable it otherwise to avoid
         * busy-looping when we're idle. */
        if (aq->defer_event_source) {
                int q = sd_event_source_set_enabled(aq->defer_event_source,
                                                   r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0) {
                        log_debug_errno(q, "Failed to toggle QMP acquirer defer source: %m");
                        return q;
                }
        }

        TAKE_PTR(aq);
        return r;
}

static int on_acquired_dispatch(void *userdata) {
        return acquired_qmp_process(userdata);
}

static int on_acquired_defer(sd_event_source *source, void *userdata) {
        assert(source);
        (void) acquired_qmp_process(userdata);
        return 1;
}

void vmspawn_qmp_proxy_broadcast_event(
                VmspawnQmpBridge *bridge,
                sd_json_variant *raw,
                const char *event,
                sd_json_variant *data) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *synth = NULL;
        int r;

        assert(bridge);
        assert(event);

        if (!bridge->acquired)
                return;

        if (!raw) {
                /* Synthetic event — reconstruct a minimal object. Acquirers tolerate
                 * the missing timestamp (the QMP spec makes it optional). */
                r = sd_json_buildo(
                                &synth,
                                SD_JSON_BUILD_PAIR_STRING("event", event),
                                SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)));
                if (r < 0) {
                        log_debug_errno(r, "Failed to build synthetic QMP event for proxy, dropping: %m");
                        return;
                }
        }

        LIST_FOREACH(acquired, aq, bridge->acquired) {
                /* Mirror QEMU's monitor: events are suppressed until the acquirer has
                 * completed its own qmp_capabilities negotiation. */
                if (!aq->caps_negotiated)
                        continue;

                r = json_stream_enqueue(&aq->stream, raw ?: synth);
                if (r < 0)
                        log_debug_errno(r, "Failed to enqueue event for QMP acquirer, dropping: %m");
        }
}

void vmspawn_qmp_proxy_drain(VmspawnQmpBridge *bridge) {
        AcquiredQmp *aq;

        if (!bridge)
                return;

        while ((aq = bridge->acquired))
                acquired_qmp_free(aq);
}

int vmspawn_qmp_proxy_acquire(VmspawnQmpBridge *bridge, sd_varlink *link) {
        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        _cleanup_(acquired_qmp_freep) AcquiredQmp *aq = NULL;
        sd_json_variant *greeting;
        sd_event *event;
        int r;

        assert(bridge);
        assert(link);

        /* Refuse unless the shared QmpClient is in the RUNNING state: only then is the
         * QEMU monitor in full command mode and the cached greeting available. Checking
         * for "not running" (rather than just "disconnected") also defends against the
         * theoretical case of AcquireQMP arriving during the bridge handshake — the
         * varlink server isn't supposed to be up that early, but we don't rely on it. */
        if (!qmp_client_is_running(bridge->qmp))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);

        greeting = qmp_client_get_greeting(bridge->qmp);
        assert(greeting); /* RUNNING implies INITIAL was dispatched, which stashed it */

        if (bridge->n_acquired >= VMSPAWN_QMP_PROXY_MAX)
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);

        event = qmp_client_get_event(bridge->qmp);
        if (!event)
                return sd_varlink_error_errno(link, ENOTCONN);

        /* Consume the upgrade. From here on `link` is closed by sd-varlink; we must
         * not touch it again even on error paths — hence the separate error returns
         * above. */
        r = sd_varlink_reply_and_upgrade(link, /* parameters= */ NULL, &input_fd, &output_fd);
        if (r < 0)
                return log_warning_errno(r, "Failed to upgrade AcquireQMP varlink connection: %m");

        aq = new(AcquiredQmp, 1);
        if (!aq)
                return -ENOMEM;

        *aq = (AcquiredQmp) {
                .bridge = bridge,
        };

        const JsonStreamParams params = {
                .delimiter = "\r\n",
                .phase     = on_acquired_phase,
                .dispatch  = on_acquired_dispatch,
                .userdata  = aq,
        };

        r = json_stream_init(&aq->stream, &params);
        if (r < 0)
                return log_warning_errno(r, "Failed to init JsonStream for QMP acquirer: %m");

        /* json_stream_connect_fd_pair adopts the fds into the stream: even on partial
         * failure (e.g. fstat inside attach_fds) the stream's input_fd/output_fd are
         * already assigned, so subsequent json_stream_done closes them. Take the fds
         * out of the local cleanup scope up front to prevent a double-close. */
        r = json_stream_connect_fd_pair(&aq->stream, TAKE_FD(input_fd), TAKE_FD(output_fd));
        if (r < 0)
                return log_warning_errno(r, "Failed to attach upgraded fds to JsonStream: %m");

        (void) json_stream_set_description(&aq->stream, "qmp-acquirer");

        r = json_stream_attach_event(&aq->stream, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_warning_errno(r, "Failed to attach QMP acquirer to event loop: %m");

        /* Defer source re-fires the dispatch loop whenever the previous step made
         * progress but there's no new I/O event to trigger the stream's io callback.
         * Mirrors qmp_client_attach_event's pattern. */
        r = sd_event_add_defer(event, &aq->defer_event_source, on_acquired_defer, aq);
        if (r < 0)
                return log_warning_errno(r, "Failed to add QMP acquirer defer source: %m");

        r = sd_event_source_set_priority(aq->defer_event_source, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_warning_errno(r, "Failed to set QMP acquirer defer priority: %m");

        r = sd_event_source_set_enabled(aq->defer_event_source, SD_EVENT_OFF);
        if (r < 0)
                return log_warning_errno(r, "Failed to disable QMP acquirer defer source: %m");

        (void) sd_event_source_set_description(aq->defer_event_source, "qmp-acquirer-defer");

        /* Replay QEMU's real greeting so the acquirer can parse it like a native
         * QMP connection. */
        r = json_stream_enqueue(&aq->stream, greeting);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue QMP greeting to acquirer: %m");

        LIST_PREPEND(acquired, bridge->acquired, aq);
        bridge->n_acquired++;
        TAKE_PTR(aq);
        return 0;
}
