/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "constants.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "log.h"
#include "memstream-util.h"
#include "oomd-manager.h"
#include "oomd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "procfs-util.h"
#include "set.h"
#include "signal-util.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-util.h"

struct OomdKillState {
        unsigned int n_ref;
        Manager *manager;
        const OomdCGroupContext *ctx;
};

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                oomd_cgroup_ctx_hash_ops,
                char,
                path_hash_func,
                path_compare,
                OomdCGroupContext,
                oomd_cgroup_context_free);

static int log_kill(const PidRef *pid, int sig, void *userdata) {
        log_debug("oomd attempting to kill " PID_FMT " with %s", pid->pid, signal_to_string(sig));
        return 0;
}

static int increment_oomd_xattr(const char *path, const char *xattr, uint64_t num_procs_killed) {
        _cleanup_free_ char *value = NULL;
        char buf[DECIMAL_STR_MAX(uint64_t) + 1];
        uint64_t curr_count = 0;
        int r;

        assert(path);
        assert(xattr);

        r = cg_get_xattr(path, xattr, &value, /* ret_size= */ NULL);
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                return r;

        if (!isempty(value)) {
                 r = safe_atou64(value, &curr_count);
                 if (r < 0)
                         return r;
        }

        if (curr_count > UINT64_MAX - num_procs_killed)
                return -EOVERFLOW;

        xsprintf(buf, "%"PRIu64, curr_count + num_procs_killed);
        r = cg_set_xattr(path, xattr, buf, strlen(buf), 0);
        if (r < 0)
                return r;

        return 0;
}

OomdCGroupContext *oomd_cgroup_context_free(OomdCGroupContext *ctx) {
        if (!ctx)
                return NULL;

        free(ctx->path);
        return mfree(ctx);
}

int oomd_pressure_above(Hashmap *h, Set **ret) {
        _cleanup_set_free_ Set *targets = NULL;
        OomdCGroupContext *ctx;
        char *key;
        int r;

        assert(h);
        assert(ret);

        targets = set_new(NULL);
        if (!targets)
                return -ENOMEM;

        HASHMAP_FOREACH_KEY(ctx, key, h) {
                if (ctx->memory_pressure.avg10 > ctx->mem_pressure_limit) {
                        usec_t diff;

                        if (ctx->mem_pressure_limit_hit_start == 0)
                                ctx->mem_pressure_limit_hit_start = now(CLOCK_MONOTONIC);

                        diff = now(CLOCK_MONOTONIC) - ctx->mem_pressure_limit_hit_start;
                        if (diff >= ctx->mem_pressure_duration_usec) {
                                r = set_put(targets, ctx);
                                if (r < 0)
                                        return -ENOMEM;
                        }
                } else
                        ctx->mem_pressure_limit_hit_start = 0;
        }

        if (!set_isempty(targets)) {
                *ret = TAKE_PTR(targets);
                return 1;
        }

        *ret = NULL;
        return 0;
}

uint64_t oomd_pgscan_rate(const OomdCGroupContext *c) {
        uint64_t last_pgscan;

        assert(c);

        /* If last_pgscan > pgscan, assume the cgroup was recreated and reset last_pgscan to zero.
         * pgscan is monotonic and in practice should not decrease (except in the recreation case). */
        last_pgscan = c->last_pgscan;
        if (c->last_pgscan > c->pgscan) {
                log_debug("Last pgscan %"PRIu64" greater than current pgscan %"PRIu64" for %s. Using last pgscan of zero.",
                                c->last_pgscan, c->pgscan, c->path);
                last_pgscan = 0;
        }

        return c->pgscan - last_pgscan;
}

bool oomd_mem_available_below(const OomdSystemContext *ctx, int threshold_permyriad) {
        uint64_t mem_threshold;

        assert(ctx);
        assert(threshold_permyriad <= 10000);

        mem_threshold = ctx->mem_total * threshold_permyriad / (uint64_t) 10000;
        return LESS_BY(ctx->mem_total, ctx->mem_used) < mem_threshold;
}

bool oomd_swap_free_below(const OomdSystemContext *ctx, int threshold_permyriad) {
        uint64_t swap_threshold;

        assert(ctx);
        assert(threshold_permyriad <= 10000);

        swap_threshold = ctx->swap_total * threshold_permyriad / (uint64_t) 10000;
        return (ctx->swap_total - ctx->swap_used) < swap_threshold;
}

int oomd_fetch_cgroup_oom_preference(OomdCGroupContext *ctx, const char *prefix) {
        uid_t uid;
        int r;

        assert(ctx);

        prefix = empty_to_root(prefix);

        if (!path_startswith(ctx->path, prefix))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s is not a descendant of %s", ctx->path, prefix);

        r = cg_get_owner(ctx->path, &uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get owner/group from %s: %m", ctx->path);

        if (uid != 0) {
                uid_t prefix_uid;

                r = cg_get_owner(prefix, &prefix_uid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get owner/group from %s: %m", prefix);

                if (uid != prefix_uid) {
                        ctx->preference = MANAGED_OOM_PREFERENCE_NONE;
                        return 0;
                }
        }

        /* Ignore most errors when reading the xattr since it is usually unset and cgroup xattrs are only used
         * as an optional feature of systemd-oomd (and the system might not even support them). */
        r = cg_get_xattr_bool(ctx->path, "user.oomd_avoid");
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                log_debug_errno(r, "Failed to get xattr user.oomd_avoid, ignoring: %m");
        ctx->preference = r > 0 ? MANAGED_OOM_PREFERENCE_AVOID : ctx->preference;

        r = cg_get_xattr_bool(ctx->path, "user.oomd_omit");
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0 && !ERRNO_IS_XATTR_ABSENT(r))
                log_debug_errno(r, "Failed to get xattr user.oomd_omit, ignoring: %m");
        ctx->preference = r > 0 ? MANAGED_OOM_PREFERENCE_OMIT : ctx->preference;

        return 0;
}

int oomd_sort_cgroup_contexts(Hashmap *h, oomd_compare_t compare_func, const char *prefix, OomdCGroupContext ***ret) {
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        OomdCGroupContext *item;
        size_t k = 0;
        int r;

        assert(h);
        assert(compare_func);
        assert(ret);

        sorted = new0(OomdCGroupContext*, hashmap_size(h));
        if (!sorted)
                return -ENOMEM;

        HASHMAP_FOREACH(item, h) {
                /* Skip over cgroups that are not valid candidates or are explicitly marked for omission */
                if (item->path && prefix && !path_startswith(item->path, prefix))
                        continue;

                r = oomd_fetch_cgroup_oom_preference(item, prefix);
                if (r == -ENOMEM)
                        return r;

                if (item->preference == MANAGED_OOM_PREFERENCE_OMIT)
                        continue;

                sorted[k++] = item;
        }

        typesafe_qsort(sorted, k, compare_func);

        *ret = TAKE_PTR(sorted);

        assert(k <= INT_MAX);
        return (int) k;
}

int oomd_cgroup_kill(const char *path, bool recurse) {
        _cleanup_set_free_ Set *pids_killed = NULL;
        int r;

        assert(path);

        pids_killed = set_new(NULL);
        if (!pids_killed)
                return -ENOMEM;

        r = increment_oomd_xattr(path, "user.oomd_ooms", 1);
        if (r < 0)
                log_debug_errno(r, "Failed to set user.oomd_ooms before kill: %m");

        if (recurse)
                r = cg_kill_recursive(path, SIGKILL, CGROUP_IGNORE_SELF, pids_killed, log_kill, NULL);
        else
                r = cg_kill(path, SIGKILL, CGROUP_IGNORE_SELF, pids_killed, log_kill, NULL);

        /* The cgroup could have been cleaned up after we have sent SIGKILL to all of the processes, but before
         * we could do one last iteration of cgroup.procs to check. Or the service unit could have exited and
         * was removed between picking candidates and coming into this function. In either case, let's log
         * about it let the caller decide what to do once they know how many PIDs were killed. */
        if (IN_SET(r, -ENOENT, -ENODEV))
                log_debug_errno(r, "Error when sending SIGKILL to processes in cgroup path %s, ignoring: %m", path);
        else if (r < 0)
                return r;

        if (set_isempty(pids_killed))
                log_debug("Nothing killed when attempting to kill %s", path);

        r = increment_oomd_xattr(path, "user.oomd_kill", set_size(pids_killed));
        if (r < 0)
                log_debug_errno(r, "Failed to set user.oomd_kill on kill: %m");

        return !set_isempty(pids_killed);
}

static void oom_kill_state_free(struct OomdKillState *ks) {
        if (ks) {
                set_remove(ks->manager->prekill_ctxs, ks);
                free(ks->ctx->path);
        }
        free(ks);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct OomdKillState*, oom_kill_state_free, NULL);

static struct OomdKillState* oomd_kill_state_dec(struct OomdKillState *ks) {
        int r = oomd_cgroup_kill(ks->ctx->path, true);
        if (r < 0)
                log_debug_errno(r, "oomd failed to kill cgroup %s: %m", ks->ctx->path);
        oom_kill_state_free(ks);
        return NULL;
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(struct OomdKillState, oomd_kill_state, oomd_kill_state_dec);

int clean_prekills(sd_event_source *e, void *userdata)
{
        struct Set *prekill_ctxs = userdata;
        struct OomdKillState *ks;

        assert(prekill_ctxs);

        SET_FOREACH(ks, prekill_ctxs) {
                log_debug("Cleaning up unfinished prekill hook state for cgroup %s", ks->ctx->path);
                oom_kill_state_free(ks);
        }

        return 0;
}

static int prekill_callback(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        struct OomdKillState *ks = ASSERT_PTR(userdata);

        if (error_id)
                log_warning("oomd prekill hook returned error: %s", error_id);
        else
                log_info("oomd prekill hook finished for cgroup %s", ks->ctx->path);

        sd_varlink_unref(link);
        oomd_kill_state_unref(ks);

        return 0;
}

static int send_prekill_message(
                const char *basename,
                sd_json_variant *cparams,
                struct OomdKillState *ks,
                sd_event *e) {

        _cleanup_(sd_varlink_close_unrefp) sd_varlink *link = NULL;
        _cleanup_free_ char *hook_path = NULL;
        int r;

        assert(basename);
        assert(cparams);
        assert(ks);
        assert(e);

        log_info("Invoking oomd prekill hook %s for cgroup %s", basename, ks->ctx->path);

        hook_path = path_join(VARLINK_ADDR_PATH_PREKILL, basename);
        if (!hook_path)
                return log_oom_debug();

        r = sd_varlink_connect_address(&link, hook_path);
        if (r < 0)
                return log_debug_errno(r, "Prekill socket at %s not connected, ignoring.", hook_path);

        (void) sd_varlink_set_userdata(link, ks);
        r = sd_varlink_set_description(link, "oomd prekill hook");
        if (r < 0)
                return log_debug_errno(r, "Failed to set varlink description: %m");
        (void) sd_varlink_set_relative_timeout(link, ks->manager->prekill_timeout);

        r = sd_varlink_attach_event(link, e, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink to event loop: %m");

        r = sd_varlink_bind_reply(link, prekill_callback);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_invoke(link, "io.systemd.oom.PreKill", cparams);
        if (r < 0)
                return log_warning_errno(r, "Failed to call varlink method io.systemd.oom.PreKill: %m");

        TAKE_PTR(link);
        oomd_kill_state_ref(ks);

        return 0;
}

static int oomd_prekill_hook(const OomdCGroupContext *ctx, Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(ctx);
        assert(m);

        d = opendir(VARLINK_ADDR_PATH_PREKILL);
        if (!d) {
                if (errno == ENOENT) {
                        log_info("No prekill varlink socket directory %s, ignoring.", VARLINK_ADDR_PATH_PREKILL);
                        return 0;
                }
                return log_debug_errno(errno, "Failed to open prekill varlink socket directory %s: %m",
                                         VARLINK_ADDR_PATH_PREKILL);
        }

        _cleanup_(oom_kill_state_freep) struct OomdKillState *ks = new(struct OomdKillState, 1);
        if (!ks)
                return log_oom_debug();

        *ks = (struct OomdKillState) {
                .n_ref = 1,
                .manager = m,
                .ctx = ctx,
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cparams = NULL;
        r = sd_json_buildo(&cparams, SD_JSON_BUILD_PAIR_STRING("cgroup", ctx->path));
        if (r < 0)
                return log_oom_debug();

        set_put(m->prekill_ctxs, ks);

        FOREACH_DIRENT(de, d, return -errno)
                if (IN_SET(de->d_type, DT_SOCK, DT_UNKNOWN))
                        (void) send_prekill_message(de->d_name, cparams, ks, m->event);

        oomd_kill_state_unref(TAKE_PTR(ks));

        return 1;
}

int oomd_cgroup_kill_mark(const OomdCGroupContext *ctx, Manager *m) {
        int r;

        assert(ctx);
        assert(m);

        if (m->dry_run) {
                _cleanup_free_ char *cg_path = NULL;

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, ctx->path, NULL, &cg_path);
                if (r < 0)
                        return r;

                log_info("oomd dry-run: Would have tried to kill %s and all its descendants", cg_path);
                return 0;
        }

        r = oomd_prekill_hook(ctx, m);
        if (r < 0)
                log_warning_errno(r, "oomd prekill hook failed for %s, ignoring: %m", ctx->path);
        else if (r > 0)
                return 0; /* Prekill hook in progress, actual kill will happen in the callback. */
        else /* If r == 0, no prekill hooks found, continue to kill immediately. */
                log_info("No oomd prekill hooks found, proceeding to kill %s and all its descendants", ctx->path);

        return oomd_cgroup_kill(ctx->path, true);
}

typedef void (*dump_candidate_func)(const OomdCGroupContext *ctx, FILE *f, const char *prefix);

static int dump_kill_candidates(
                OomdCGroupContext *sorted[],
                size_t n,
                const OomdCGroupContext *killed,
                dump_candidate_func dump_func) {

        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        /* Try dumping top offendors, ignoring any errors that might happen. */

        assert(sorted || n == 0);
        assert(dump_func);

        /* If nothing killed, then limit the number of contexts to be dumped, for safety. */
        if (!killed)
                n = MIN(n, DUMP_ON_KILL_COUNT);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        fprintf(f, "Considered %zu cgroups for killing, top candidates were:\n", n);
        FOREACH_ARRAY(i, sorted, n) {
                const OomdCGroupContext *c = *i;

                dump_func(c, f, "\t");

                if (c == killed)
                        break;
        }

        return memstream_dump(LOG_INFO, &m);
}

int oomd_select_by_pgscan_rate(Hashmap *h, const char *prefix, const OomdCGroupContext **ret_selected) {
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        const OomdCGroupContext *killed = NULL;
        int n;

        assert(h);
        assert(ret_selected);

        n = oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, prefix, &sorted);
        if (n < 0)
                return n;

        (void) dump_kill_candidates(sorted, n, killed, oomd_dump_memory_pressure_cgroup_context);

        FOREACH_ARRAY(i, sorted, n) {
                const OomdCGroupContext *c = *i;

                /* Skip cgroups with no reclaim and memory usage; it won't alleviate pressure.
                 * Continue since there might be "avoid" cgroups at the end. */
                if (c->pgscan == 0 && c->current_memory_usage == 0)
                        continue;

                *ret_selected = TAKE_PTR(c);

                return 1;
        }

        return 0;
}

int oomd_select_by_swap_usage(Hashmap *h, uint64_t threshold_usage, const OomdCGroupContext **ret_selected) {
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        const OomdCGroupContext *killed = NULL;
        int n;

        assert(h);
        assert(ret_selected);

        n = oomd_sort_cgroup_contexts(h, compare_swap_usage, NULL, &sorted);
        if (n < 0)
                return n;

        (void) dump_kill_candidates(sorted, n, killed, oomd_dump_swap_cgroup_context);

        /* Try to kill cgroups with non-zero swap usage until we either succeed in killing or we get to a cgroup with
         * no swap usage. Threshold killing only cgroups with more than threshold swap usage. */

        FOREACH_ARRAY(i, sorted, n) {
                const OomdCGroupContext *c = *i;

                /* Skip over cgroups with not enough swap usage. Don't break since there might be "avoid"
                 * cgroups at the end. */
                if (c->swap_usage <= threshold_usage)
                        continue;

                *ret_selected = TAKE_PTR(c);

                return 1;
        }

        return 0;
}

int oomd_cgroup_context_acquire(const char *path, OomdCGroupContext **ret) {
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        _cleanup_free_ char *p = NULL, *val = NULL;
        bool is_root;
        int r;

        assert(path);
        assert(ret);

        ctx = new0(OomdCGroupContext, 1);
        if (!ctx)
                return -ENOMEM;

        is_root = empty_or_root(path);
        ctx->preference = MANAGED_OOM_PREFERENCE_NONE;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, path, "memory.pressure", &p);
        if (r < 0)
                return log_debug_errno(r, "Error getting cgroup memory pressure path from %s: %m", path);

        r = read_resource_pressure(p, PRESSURE_TYPE_FULL, &ctx->memory_pressure);
        if (r < 0)
                return log_debug_errno(r, "Error parsing memory pressure from %s: %m", p);

        if (is_root) {
                r = procfs_memory_get_used(&ctx->current_memory_usage);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory used from procfs: %m");
        } else {
                r = cg_get_attribute_as_uint64(SYSTEMD_CGROUP_CONTROLLER, path, "memory.current", &ctx->current_memory_usage);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.current from %s: %m", path);

                r = cg_get_attribute_as_uint64(SYSTEMD_CGROUP_CONTROLLER, path, "memory.min", &ctx->memory_min);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.min from %s: %m", path);

                r = cg_get_attribute_as_uint64(SYSTEMD_CGROUP_CONTROLLER, path, "memory.low", &ctx->memory_low);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.low from %s: %m", path);

                r = cg_get_attribute_as_uint64(SYSTEMD_CGROUP_CONTROLLER, path, "memory.swap.current", &ctx->swap_usage);
                if (r == -ENODATA)
                        /* The kernel can be compiled without support for memory.swap.* files,
                         * or it can be disabled with boot param 'swapaccount=0' */
                        log_once(LOG_WARNING, "No kernel support for memory.swap.current from %s (try boot param swapaccount=1), ignoring.", path);
                else if (r < 0)
                        return log_debug_errno(r, "Error getting memory.swap.current from %s: %m", path);

                r = cg_get_keyed_attribute(SYSTEMD_CGROUP_CONTROLLER, path, "memory.stat", STRV_MAKE("pgscan"), &val);
                if (r < 0)
                        return log_debug_errno(r, "Error getting pgscan from memory.stat under %s: %m", path);

                r = safe_atou64(val, &ctx->pgscan);
                if (r < 0)
                        return log_debug_errno(r, "Error converting pgscan value to uint64_t: %m");
        }

        r = strdup_to(&ctx->path, empty_to_root(path));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(ctx);
        return 0;
}

int oomd_system_context_acquire(const char *proc_meminfo_path, OomdSystemContext *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned field_filled = 0;
        OomdSystemContext ctx = {};
        uint64_t mem_available, swap_free;
        int r;

        enum {
                MEM_TOTAL = 1U << 0,
                MEM_AVAILABLE = 1U << 1,
                SWAP_TOTAL = 1U << 2,
                SWAP_FREE = 1U << 3,
                ALL = MEM_TOTAL|MEM_AVAILABLE|SWAP_TOTAL|SWAP_FREE,
        };

        assert(proc_meminfo_path);
        assert(ret);

        f = fopen(proc_meminfo_path, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *word;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;

                if ((word = startswith(line, "MemTotal:"))) {
                        field_filled |= MEM_TOTAL;
                        r = convert_meminfo_value_to_uint64_bytes(word, &ctx.mem_total);
                } else if ((word = startswith(line, "MemAvailable:"))) {
                        field_filled |= MEM_AVAILABLE;
                        r = convert_meminfo_value_to_uint64_bytes(word, &mem_available);
                } else if ((word = startswith(line, "SwapTotal:"))) {
                        field_filled |= SWAP_TOTAL;
                        r = convert_meminfo_value_to_uint64_bytes(word, &ctx.swap_total);
                } else if ((word = startswith(line, "SwapFree:"))) {
                        field_filled |= SWAP_FREE;
                        r = convert_meminfo_value_to_uint64_bytes(word, &swap_free);
                } else
                        continue;

                if (r < 0)
                        return log_debug_errno(r, "Error converting '%s' from %s to uint64_t: %m", line, proc_meminfo_path);

                if (field_filled == ALL)
                        break;
        }

        if (field_filled != ALL)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "%s is missing expected fields", proc_meminfo_path);

        if (mem_available > ctx.mem_total)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "MemAvailable (%" PRIu64 ") cannot be greater than MemTotal (%" PRIu64 ")",
                                       mem_available,
                                       ctx.mem_total);

        if (swap_free > ctx.swap_total)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "SwapFree (%" PRIu64 ") cannot be greater than SwapTotal (%" PRIu64 ")",
                                       swap_free,
                                       ctx.swap_total);

        ctx.mem_used = ctx.mem_total - mem_available;
        ctx.swap_used = ctx.swap_total - swap_free;

        *ret = ctx;
        return 0;
}

int oomd_insert_cgroup_context(Hashmap *old_h, Hashmap *new_h, const char *path) {
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *curr_ctx = NULL;
        OomdCGroupContext *old_ctx;
        int r;

        assert(new_h);
        assert(path);

        path = empty_to_root(path);

        r = oomd_cgroup_context_acquire(path, &curr_ctx);
        if (r < 0)
                return log_debug_errno(r, "Failed to get OomdCGroupContext for %s: %m", path);

        assert_se(streq(path, curr_ctx->path));

        old_ctx = hashmap_get(old_h, path);
        if (old_ctx) {
                curr_ctx->last_pgscan = old_ctx->pgscan;
                curr_ctx->mem_pressure_limit = old_ctx->mem_pressure_limit;
                curr_ctx->mem_pressure_limit_hit_start = old_ctx->mem_pressure_limit_hit_start;
                curr_ctx->mem_pressure_duration_usec = old_ctx->mem_pressure_duration_usec;
                curr_ctx->last_had_mem_reclaim = old_ctx->last_had_mem_reclaim;
        }

        if (oomd_pgscan_rate(curr_ctx) > 0)
                curr_ctx->last_had_mem_reclaim = now(CLOCK_MONOTONIC);

        r = hashmap_put(new_h, curr_ctx->path, curr_ctx);
        if (r < 0)
                return r;

        TAKE_PTR(curr_ctx);
        return 0;
}

void oomd_update_cgroup_contexts_between_hashmaps(Hashmap *old_h, Hashmap *curr_h) {
        OomdCGroupContext *ctx;

        assert(old_h);
        assert(curr_h);

        HASHMAP_FOREACH(ctx, curr_h) {
                OomdCGroupContext *old_ctx;

                old_ctx = hashmap_get(old_h, ctx->path);
                if (!old_ctx)
                        continue;

                ctx->last_pgscan = old_ctx->pgscan;
                ctx->mem_pressure_limit = old_ctx->mem_pressure_limit;
                ctx->mem_pressure_limit_hit_start = old_ctx->mem_pressure_limit_hit_start;
                ctx->mem_pressure_duration_usec = old_ctx->mem_pressure_duration_usec;
                ctx->last_had_mem_reclaim = old_ctx->last_had_mem_reclaim;

                if (oomd_pgscan_rate(ctx) > 0)
                        ctx->last_had_mem_reclaim = now(CLOCK_MONOTONIC);
        }
}

void oomd_dump_swap_cgroup_context(const OomdCGroupContext *ctx, FILE *f, const char *prefix) {
        assert(ctx);
        assert(f);

        if (!empty_or_root(ctx->path))
                fprintf(f,
                        "%sPath: %s\n"
                        "%s\tSwap Usage: %s\n",
                        strempty(prefix), ctx->path,
                        strempty(prefix), FORMAT_BYTES(ctx->swap_usage));
        else
                fprintf(f,
                        "%sPath: %s\n"
                        "%s\tSwap Usage: (see System Context)\n",
                        strempty(prefix), ctx->path,
                        strempty(prefix));
}

void oomd_dump_memory_pressure_cgroup_context(const OomdCGroupContext *ctx, FILE *f, const char *prefix) {
        assert(ctx);
        assert(f);

        fprintf(f,
                "%sPath: %s\n"
                "%s\tMemory Pressure Limit: %lu.%02lu%%\n"
                "%s\tMemory Pressure Duration: %s\n"
                "%s\tPressure: Avg10: %lu.%02lu, Avg60: %lu.%02lu, Avg300: %lu.%02lu, Total: %s\n"
                "%s\tCurrent Memory Usage: %s\n",
                strempty(prefix), ctx->path,
                strempty(prefix), LOADAVG_INT_SIDE(ctx->mem_pressure_limit), LOADAVG_DECIMAL_SIDE(ctx->mem_pressure_limit),
                strempty(prefix), FORMAT_TIMESPAN(ctx->mem_pressure_duration_usec, USEC_PER_SEC),
                strempty(prefix),
                LOADAVG_INT_SIDE(ctx->memory_pressure.avg10), LOADAVG_DECIMAL_SIDE(ctx->memory_pressure.avg10),
                LOADAVG_INT_SIDE(ctx->memory_pressure.avg60), LOADAVG_DECIMAL_SIDE(ctx->memory_pressure.avg60),
                LOADAVG_INT_SIDE(ctx->memory_pressure.avg300), LOADAVG_DECIMAL_SIDE(ctx->memory_pressure.avg300),
                FORMAT_TIMESPAN(ctx->memory_pressure.total, USEC_PER_SEC),
                strempty(prefix), FORMAT_BYTES(ctx->current_memory_usage));

        if (!empty_or_root(ctx->path))
                fprintf(f,
                        "%s\tMemory Min: %s\n"
                        "%s\tMemory Low: %s\n"
                        "%s\tPgscan: %" PRIu64 "\n"
                        "%s\tLast Pgscan: %" PRIu64 "\n",
                        strempty(prefix), FORMAT_BYTES_CGROUP_PROTECTION(ctx->memory_min),
                        strempty(prefix), FORMAT_BYTES_CGROUP_PROTECTION(ctx->memory_low),
                        strempty(prefix), ctx->pgscan,
                        strempty(prefix), ctx->last_pgscan);
}

void oomd_dump_system_context(const OomdSystemContext *ctx, FILE *f, const char *prefix) {
        assert(ctx);
        assert(f);

        fprintf(f,
                "%sMemory: Used: %s, Total: %s\n"
                "%sSwap: Used: %s, Total: %s\n",
                strempty(prefix),
                FORMAT_BYTES(ctx->mem_used),
                FORMAT_BYTES(ctx->mem_total),
                strempty(prefix),
                FORMAT_BYTES(ctx->swap_used),
                FORMAT_BYTES(ctx->swap_total));
}
