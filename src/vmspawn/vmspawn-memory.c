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

/* Debug logs show sizes in exact KiB rather than through format_bytes(): its 0.1 precision cannot
 * show the 64 KiB rounding of SetMemory() or a guest that stops a few MiB short of its target. */
static const char* format_kib(char *buf, size_t l, uint64_t bytes) {
        assert(buf);

        (void) snprintf(buf, l, "%" PRIu64 " KiB", bytes / U64_KB);
        return buf;
}

#define FORMAT_KIB_MAX (DECIMAL_STR_MAX(uint64_t) + STRLEN(" KiB"))
#define FORMAT_KIB(bytes) format_kib((char[FORMAT_KIB_MAX]){}, FORMAT_KIB_MAX, bytes)

/* Partial convergence is normal (unmovable pages, deflate-on-oom). QEMU throttles
 * BALLOON_CHANGE to one per second, so this is several missed updates. */
#define MEMORY_STALL_TIMEOUT_USEC (5 * USEC_PER_SEC)

#define BALLOON_QOM_PATH "/machine/peripheral/balloon0"
#define BALLOON_STATS_POLL_INTERVAL_SEC 2

static uint64_t stat_value(sd_json_variant *stats, const char *name) {
        sd_json_variant *v = sd_json_variant_by_key(stats, name);
        if (!v || !sd_json_variant_is_unsigned(v))
                return UINT64_MAX;
        return sd_json_variant_unsigned(v);
}

int vmspawn_memory_stats_parse(sd_json_variant *v, VmspawnMemoryStats *ret) {
        sd_json_variant *stats, *last_update;
        uint64_t total_mem, free_mem;

        assert(v);
        assert(ret);

        stats = sd_json_variant_by_key(v, "stats");
        last_update = sd_json_variant_by_key(v, "last-update");
        if (!stats || !sd_json_variant_is_object(stats) || !last_update || !sd_json_variant_is_unsigned(last_update))
                return -EBADMSG;
        if (sd_json_variant_unsigned(last_update) == 0)
                return -ENODATA;

        total_mem = stat_value(stats, "stat-total-memory");
        free_mem = stat_value(stats, "stat-free-memory");
        if (total_mem == UINT64_MAX || free_mem == UINT64_MAX)
                return -ENODATA;

        *ret = (VmspawnMemoryStats) {
                .last_update = sd_json_variant_unsigned(last_update) * USEC_PER_SEC,
                .total = total_mem,
                .free = free_mem,
                .available = stat_value(stats, "stat-available-memory"),
                .disk_caches = stat_value(stats, "stat-disk-caches"),
                .swap_in = stat_value(stats, "stat-swap-in"),
                .swap_out = stat_value(stats, "stat-swap-out"),
                .major_faults = stat_value(stats, "stat-major-faults"),
                .minor_faults = stat_value(stats, "stat-minor-faults"),
                .hugetlb_allocations = stat_value(stats, "stat-htlb-pgalloc"),
                .hugetlb_failures = stat_value(stats, "stat-htlb-pgfail"),
                .oom_kills = stat_value(stats, "stat-oom-kills"),
                .alloc_stalls = stat_value(stats, "stat-alloc-stalls"),
                .async_scans = stat_value(stats, "stat-async-scans"),
                .direct_scans = stat_value(stats, "stat-direct-scans"),
                .async_reclaims = stat_value(stats, "stat-async-reclaims"),
                .direct_reclaims = stat_value(stats, "stat-direct-reclaims"),
        };
        return 0;
}

static int on_get_stats_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnMemory *m = ASSERT_PTR(userdata);
        VmspawnMemoryStats stats;
        int r;

        assert(client);

        m->stats_get_inflight = false;

        if (error < 0) {
                log_debug_errno(error, "Failed to get memory stats, ignoring: %s", strna(error_desc));
                return 0;
        }

        r = vmspawn_memory_stats_parse(result, &stats);
        if (r == -ENODATA)
                return 0;
        if (r < 0) {
                log_debug_errno(r, "Failed to parse memory stats, ignoring: %m");
                return 0;
        }

        m->stats = stats;
        return 0;
}

static int on_stats_timer(sd_event_source *s, uint64_t usec, void *userdata);

static int memory_stats_rearm(VmspawnMemory *m) {
        assert(m);

        return event_reset_time_relative(
                        qmp_client_get_event(m->bridge->qmp),
                        &m->stats_timer,
                        CLOCK_MONOTONIC,
                        BALLOON_STATS_POLL_INTERVAL_SEC * USEC_PER_SEC,
                        /* accuracy= */ 0,
                        on_stats_timer,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "vmspawn-memory-stats",
                        /* force_reset= */ true);
}

static int memory_get_stats(VmspawnMemory *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(m);

        if (m->stats_get_inflight)
                return 0;

        r = sd_json_buildo(&args,
                           SD_JSON_BUILD_PAIR_STRING("path", BALLOON_QOM_PATH),
                           SD_JSON_BUILD_PAIR_STRING("property", "guest-stats"));
        if (r < 0)
                return r;

        r = qmp_client_invoke(
                        m->bridge->qmp,
                        /* ret_slot= */ NULL,
                        "qom-get",
                        QMP_CLIENT_ARGS(args),
                        on_get_stats_complete,
                        m);
        if (r < 0)
                return r;

        m->stats_get_inflight = true;

        return 0;
}

static int on_stats_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        VmspawnMemory *m = ASSERT_PTR(userdata);
        int r;

        if (qmp_client_is_disconnected(m->bridge->qmp))
                return 0;

        r = memory_get_stats(m);
        if (r < 0)
                log_debug_errno(r, "Failed to request memory stats, ignoring: %m");

        return memory_stats_rearm(m);
}

static int on_stats_polling_enabled(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnMemory *m = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                log_full_errno(error == -ECONNRESET ? LOG_DEBUG : LOG_WARNING, error,
                               "Failed to enable memory stats polling, ignoring: %s", strna(error_desc));
                return 0;
        }

        return memory_stats_rearm(m);
}

static int memory_enable_stats_polling(VmspawnMemory *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(m);
        assert(m->bridge);

        if (!m->balloon)
                return 0;

        r = sd_json_buildo(&args,
                           SD_JSON_BUILD_PAIR_STRING("path", BALLOON_QOM_PATH),
                           SD_JSON_BUILD_PAIR_STRING("property", "guest-stats-polling-interval"),
                           SD_JSON_BUILD_PAIR_UNSIGNED("value", BALLOON_STATS_POLL_INTERVAL_SEC));
        if (r < 0)
                return r;

        return qmp_client_invoke(
                        m->bridge->qmp,
                        /* ret_slot= */ NULL,
                        "qom-set",
                        QMP_CLIENT_ARGS(args),
                        on_stats_polling_enabled,
                        m);
}

VmspawnMemory* vmspawn_memory_free(VmspawnMemory *m) {
        if (!m)
                return NULL;

        sd_event_source_disable_unref(m->stall_timer);
        sd_event_source_disable_unref(m->stats_timer);
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
                r = sd_varlink_error(link, error, /* parameters= */ NULL);
        else if (error_errno < 0)
                r = sd_varlink_error_errno(link, error_errno);
        else
                r = memory_send_progress(m, link, /* final= */ true);
        if (r < 0)
                log_debug_errno(r, "Failed to end SetMemory() call, ignoring: %m");
}

static int on_stall_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        VmspawnMemory *m = ASSERT_PTR(userdata);

        log_debug("Guest memory size stopped at %s, short of target %s.",
                  FORMAT_KIB(m->actual), FORMAT_KIB(m->target));

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

        log_debug("Guest memory size is now %s (target %s).", FORMAT_KIB(actual), FORMAT_KIB(m->target));
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
        log_debug("Requested guest memory size %s.", FORMAT_KIB(req->bytes));

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

        r = memory_enable_stats_polling(bridge->memory);
        if (r < 0)
                return log_error_errno(r, "Failed to enable memory stats polling: %m");

        return 0;
}

void vmspawn_memory_disconnect(VmspawnMemory *m) {
        if (!m)
                return;

        memory_end_progress(m, "io.systemd.MachineInstance.NotConnected", /* error_errno= */ 0);
}

int vmspawn_memory_dispatch_balloon_change(VmspawnMemory *m, sd_json_variant *data) {
        assert(m);

        if (!data)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "BALLOON_CHANGE event without payload, ignoring.");

        return memory_update_actual(m, data);
}

static int memory_build_stats_json(const VmspawnMemory *m, sd_json_variant **ret) {
        assert(m);
        assert(ret);

        if (m->stats.last_update == 0) {
                *ret = NULL;
                return 0;
        }

        const VmspawnMemoryStats *s = &m->stats;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("lastUpdateUSec", s->last_update),
                        SD_JSON_BUILD_PAIR_UNSIGNED("totalBytes", s->total),
                        SD_JSON_BUILD_PAIR_UNSIGNED("freeBytes", s->free),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("availableBytes", s->available, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("diskCachesBytes", s->disk_caches, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("swapInBytes", s->swap_in, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("swapOutBytes", s->swap_out, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("majorFaults", s->major_faults, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minorFaults", s->minor_faults, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("hugetlbAllocations", s->hugetlb_allocations, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("hugetlbFailures", s->hugetlb_failures, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("oomKills", s->oom_kills, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("allocStalls", s->alloc_stalls, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("asyncScansBytes", s->async_scans, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("directScansBytes", s->direct_scans, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("asyncReclaimsBytes", s->async_reclaims, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("directReclaimsBytes", s->direct_reclaims, UINT64_MAX));
}

int vmspawn_memory_build_json(VmspawnMemory *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *stats = NULL;
        int r;

        assert(m);
        assert(ret);

        r = memory_build_stats_json(m, &stats);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("configuredBytes", m->configured),
                        SD_JSON_BUILD_PAIR_UNSIGNED("targetBytes", m->target),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("actualBytes", m->actual),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("stats", stats));
}
