/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "event-util.h"
#include "json-util.h"
#include "log.h"
#include "memory-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "time-util.h"
#include "vmspawn-memory.h"
#include "vmspawn-qmp.h"

/* Partial convergence is normal (unmovable pages, deflate-on-oom). QEMU throttles
 * BALLOON_CHANGE to one per second, so this is several missed updates. */
#define MEMORY_STALL_TIMEOUT_USEC (5 * USEC_PER_SEC)

VmspawnMemory* vmspawn_memory_free(VmspawnMemory *m) {
        if (!m)
                return NULL;

        sd_event_source_disable_unref(m->stall_timer);
        sd_varlink_unref(m->progress_link);
        return mfree(m);
}

static int memory_send_progress(VmspawnMemory *m, sd_varlink *link, bool final) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(m);
        assert(link);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_UNSIGNED("targetBytes", m->target),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("actualBytes", m->actual));
        if (r < 0)
                return r;

        return final ? sd_varlink_reply(link, v) : sd_varlink_notify(link, v);
}

/* Ends a pending SetMemory() call with 'more': with 'error' if set, else with 'error_errno' if negative,
 * else with the final reply. */
static void memory_end_progress(VmspawnMemory *m, const char *error, int error_errno) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        int r;

        assert(m);

        m->stall_timer = sd_event_source_disable_unref(m->stall_timer);

        link = TAKE_PTR(m->progress_link);
        if (!link)
                return;

        if (error)
                r = sd_varlink_error(link, error, NULL);
        else if (error_errno < 0)
                r = sd_varlink_error_errno(link, error_errno);
        else
                r = memory_send_progress(m, link, /* final= */ true);
        if (r < 0)
                log_debug_errno(r, "Failed to end SetMemory() call, ignoring: %m");
}

static int on_stall_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        VmspawnMemory *m = ASSERT_PTR(userdata);

        log_debug("Guest memory size stopped at %" PRIu64 " KiB, short of target %" PRIu64 " KiB.",
                  m->actual / U64_KB, m->target / U64_KB);

        memory_end_progress(m, /* error= */ NULL, /* error_errno= */ 0);
        return 0;
}

static int memory_progress_rearm(VmspawnMemory *m) {
        assert(m);

        return event_reset_time_relative(
                        qmp_client_get_event(m->bridge->qmp),
                        &m->stall_timer,
                        CLOCK_MONOTONIC,
                        MEMORY_STALL_TIMEOUT_USEC,
                        /* accuracy= */ 0,
                        on_stall_timer,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "vmspawn-memory-stall",
                        /* force_reset= */ true);
}

static int memory_update_actual(VmspawnMemory *m, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "actual", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, 0, SD_JSON_MANDATORY },
                {}
        };
        uint64_t actual, previous;
        int r;

        assert(m);

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &actual);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse balloon size reported by QEMU, ignoring: %m");

        if (actual == m->actual)
                return 0;

        log_debug("Guest memory size is now %" PRIu64 " KiB (target %" PRIu64 " KiB).",
                  actual / U64_KB, m->target / U64_KB);
        previous = m->actual;
        m->actual = actual;

        if (!m->progress_link)
                return 0;

        /* Also end the call once the guest moves away from the target, e.g. on deflate-on-oom, so that
         * a guest moving its balloon back and forth cannot hold it open forever. */
        if (actual == m->target ||
            (previous > 0 && ABS_DIFF(actual, m->target) >= ABS_DIFF(previous, m->target))) {
                memory_end_progress(m, /* error= */ NULL, /* error_errno= */ 0);
                return 0;
        }

        r = memory_send_progress(m, m->progress_link, /* final= */ false);
        if (r >= 0)
                r = memory_progress_rearm(m);
        if (r < 0) {
                log_debug_errno(r, "Failed to continue SetMemory() call, ending it: %m");
                memory_end_progress(m, /* error= */ NULL, r);
        }

        return 0;
}

static int on_query_balloon_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnMemory *m = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                log_debug_errno(error, "query-balloon failed, ignoring: %s", strna(error_desc));
                return 0;
        }

        (void) memory_update_actual(m, result);
        return 0;
}

typedef struct SetTargetRequest {
        VmspawnMemory *m;
        sd_varlink *link;       /* ref'd */
        uint64_t bytes;
        bool more;
} SetTargetRequest;

static SetTargetRequest* set_target_request_free(SetTargetRequest *req) {
        if (!req)
                return NULL;

        sd_varlink_unref(req->link);
        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SetTargetRequest*, set_target_request_free);

static int on_balloon_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(set_target_request_freep) SetTargetRequest *req = ASSERT_PTR(userdata);
        VmspawnMemory *m = req->m;
        int r;

        assert(client);

        if (error < 0)
                return vmspawn_qmp_reply_error(req->link, error_desc, error);

        m->target = req->bytes;
        log_debug("Requested guest memory size %" PRIu64 " KiB.", req->bytes / U64_KB);

        /* There is one target at a time, so a call still waiting for the previous one ends here. */
        memory_end_progress(m, "io.systemd.MachineInstance.Superseded", /* error_errno= */ 0);

        if (!req->more || m->actual == m->target)
                return memory_send_progress(m, req->link, /* final= */ true);

        r = memory_progress_rearm(m);
        if (r < 0)
                return sd_varlink_error_errno(req->link, r);

        m->progress_link = TAKE_PTR(req->link);
        return 0;
}

static int memory_refresh(VmspawnMemory *m) {
        assert(m);
        assert(m->bridge);

        if (!m->balloon)
                return 0;

        return qmp_client_invoke(m->bridge->qmp,
                                 /* ret_slot= */ NULL,
                                 "query-balloon",
                                 /* args= */ NULL,
                                 on_query_balloon_complete,
                                 m);
}

int vmspawn_memory_set_target(VmspawnMemory *m, sd_varlink *link, bool more, uint64_t bytes) {
        _cleanup_(set_target_request_freep) SetTargetRequest *req = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(m);
        assert(m->bridge);
        assert(link);

        if (!m->balloon)
                return -EOPNOTSUPP;
        if (bytes == 0 || bytes > m->configured)
                return -ERANGE;

        /* The balloon counts 4 KiB pages, but the guest rounds that count up to its own page size, which
         * is 64 KiB at most on Linux. Round up to that, so that the guest can settle exactly on the
         * target instead of below it. Boot RAM is MiB-aligned, so this stays within range. */
        bytes = ALIGN_TO_U64(bytes, 64 * U64_KB);

        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("value", bytes));
        if (r < 0)
                return r;

        req = new(SetTargetRequest, 1);
        if (!req)
                return -ENOMEM;

        *req = (SetTargetRequest) {
                .m = m,
                .link = sd_varlink_ref(link),
                .bytes = bytes,
                .more = more,
        };

        r = qmp_client_invoke(m->bridge->qmp,
                              /* ret_slot= */ NULL,
                              "balloon",
                              QMP_CLIENT_ARGS(args),
                              on_balloon_complete,
                              req);
        if (r < 0)
                return r;

        TAKE_PTR(req);
        return 0;
}

int vmspawn_memory_setup(VmspawnQmpBridge *bridge, uint64_t configured, bool balloon) {
        _cleanup_(vmspawn_memory_freep) VmspawnMemory *m = NULL;
        int r;

        assert(bridge);
        assert(!bridge->memory);

        m = new(VmspawnMemory, 1);
        if (!m)
                return log_oom();

        *m = (VmspawnMemory) {
                .bridge = bridge,
                .configured = configured,
                .target = configured,
                .actual = balloon ? 0 : configured,
                .balloon = balloon,
        };

        bridge->memory = TAKE_PTR(m);

        r = memory_refresh(bridge->memory);
        if (r < 0)
                return log_error_errno(r, "Failed to send query-balloon: %m");

        return 0;
}

void vmspawn_memory_disconnect(VmspawnMemory *m) {
        assert(m);

        memory_end_progress(m, "io.systemd.MachineInstance.NotConnected", /* error_errno= */ 0);
}

int vmspawn_memory_dispatch_balloon_change(VmspawnMemory *m, sd_json_variant *data) {
        assert(m);

        if (!data)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "BALLOON_CHANGE event without payload, ignoring.");

        return memory_update_actual(m, data);
}

int vmspawn_memory_build_json(VmspawnMemory *m, sd_json_variant **ret) {
        assert(m);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("configuredBytes", m->configured),
                        SD_JSON_BUILD_PAIR_UNSIGNED("targetBytes", m->target),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("actualBytes", m->actual));
}
