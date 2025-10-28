/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "log.h"
#include "memstream-util.h"
#include "oomd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "procfs-util.h"
#include "set.h"
#include "signal-util.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                oomd_cgroup_ctx_hash_ops,
                char,
                path_hash_func,
                path_compare,
                OomdCGroupContext,
                oomd_cgroup_context_unref);

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

static OomdCGroupContext *oomd_cgroup_context_free(OomdCGroupContext *ctx) {
        if (!ctx)
                return NULL;

        free(ctx->path);
        return mfree(ctx);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(OomdCGroupContext, oomd_cgroup_context, oomd_cgroup_context_free);

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

int oomd_cgroup_kill(const char *path, bool recurse, bool dry_run) {
        _cleanup_set_free_ Set *pids_killed = NULL;
        int r;

        assert(path);

        /* First try to send SIG0 recursively to ensure all child cgroups can be killed. */
        if (recurse)
                r = cg_kill_recursive(path, /* sig= */ 0, CGROUP_IGNORE_SELF,
                                      /* killed_pids= */ NULL, /* log_kill= */ NULL, /* userdata= */ NULL);
        else
                r = cg_kill(path, /* sig= */ 0, CGROUP_IGNORE_SELF,
                            /* killed_pids= */ NULL, /* log_kill= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to send SIG0 to processes in cgroup '%s': %m", path);

        if (dry_run) {
                _cleanup_free_ char *cg_path = NULL;

                r = cg_get_path(path, /* suffix= */ NULL, &cg_path);
                if (r < 0)
                        return r;

                log_info("oomd dry-run: Would have tried to kill %s with recurse=%s", cg_path, true_false(recurse));
                return 0;
        }

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

int oomd_kill_by_pgscan_rate(Hashmap *h, const char *prefix, bool dry_run, char **ret_selected) {
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        const OomdCGroupContext *killed = NULL;
        int n, r, ret = 0;

        assert(h);
        assert(ret_selected);

        n = oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, prefix, &sorted);
        if (n < 0)
                return n;

        FOREACH_ARRAY(i, sorted, n) {
                const OomdCGroupContext *c = *i;

                /* Skip cgroups with no reclaim and memory usage; it won't alleviate pressure.
                 * Continue since there might be "avoid" cgroups at the end. */
                if (c->pgscan == 0 && c->current_memory_usage == 0)
                        continue;

                r = oomd_cgroup_kill(c->path, /* recurse= */ true, /* dry_run= */ dry_run);
                if (r == -ENOMEM)
                        return r; /* Treat oom as a hard error */
                if (r < 0) {
                        RET_GATHER(ret, r);
                        continue; /* Try to find something else to kill */
                }

                ret = r;
                r = strdup_to(ret_selected, c->path);
                if (r < 0)
                        return r;

                killed = c;
                break;
        }

        (void) dump_kill_candidates(sorted, n, killed, oomd_dump_memory_pressure_cgroup_context);
        return ret;
}

int oomd_kill_by_swap_usage(Hashmap *h, uint64_t threshold_usage, bool dry_run, char **ret_selected) {
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        const OomdCGroupContext *killed = NULL;
        int n, r, ret = 0;

        assert(h);
        assert(ret_selected);

        n = oomd_sort_cgroup_contexts(h, compare_swap_usage, NULL, &sorted);
        if (n < 0)
                return n;

        /* Try to kill cgroups with non-zero swap usage until we either succeed in killing or we get to a cgroup with
         * no swap usage. Threshold killing only cgroups with more than threshold swap usage. */

        FOREACH_ARRAY(i, sorted, n) {
                const OomdCGroupContext *c = *i;

                /* Skip over cgroups with not enough swap usage. Don't break since there might be "avoid"
                 * cgroups at the end. */
                if (c->swap_usage <= threshold_usage)
                        continue;

                r = oomd_cgroup_kill(c->path, /* recurse= */ true, /* dry_run= */ dry_run);
                if (r == -ENOMEM)
                        return r; /* Treat oom as a hard error */
                if (r < 0) {
                        RET_GATHER(ret, r);
                        continue; /* Try to find something else to kill */
                }

                ret = r;
                r = strdup_to(ret_selected, c->path);
                if (r < 0)
                        return r;

                killed = c;
                break;
        }

        (void) dump_kill_candidates(sorted, n, killed, oomd_dump_swap_cgroup_context);
        return ret;
}

int oomd_cgroup_context_acquire(const char *path, OomdCGroupContext **ret) {
        _cleanup_(oomd_cgroup_context_unrefp) OomdCGroupContext *ctx = NULL;
        _cleanup_free_ char *p = NULL, *val = NULL;
        bool is_root;
        int r;

        assert(path);
        assert(ret);

        ctx = new0(OomdCGroupContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (OomdCGroupContext) {
                .n_ref = 1,
                .preference = MANAGED_OOM_PREFERENCE_NONE,
                .path = strdup(empty_to_root(path)),
        };
        if (!ctx->path)
                return -ENOMEM;

        is_root = empty_or_root(path);

        r = cg_get_path(path, "memory.pressure", &p);
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
                r = cg_get_attribute_as_uint64(path, "memory.current", &ctx->current_memory_usage);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.current from %s: %m", path);

                r = cg_get_attribute_as_uint64(path, "memory.min", &ctx->memory_min);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.min from %s: %m", path);

                r = cg_get_attribute_as_uint64(path, "memory.low", &ctx->memory_low);
                if (r < 0)
                        return log_debug_errno(r, "Error getting memory.low from %s: %m", path);

                r = cg_get_attribute_as_uint64(path, "memory.swap.current", &ctx->swap_usage);
                if (r == -ENODATA)
                        /* The kernel can be compiled without support for memory.swap.* files,
                         * or it can be disabled with boot param 'swapaccount=0' */
                        log_once(LOG_WARNING, "No kernel support for memory.swap.current from %s (try boot param swapaccount=1), ignoring.", path);
                else if (r < 0)
                        return log_debug_errno(r, "Error getting memory.swap.current from %s: %m", path);

                r = cg_get_keyed_attribute(path, "memory.stat", STRV_MAKE("pgscan"), &val);
                if (r < 0)
                        return log_debug_errno(r, "Error getting pgscan from memory.stat under %s: %m", path);

                r = safe_atou64(val, &ctx->pgscan);
                if (r < 0)
                        return log_debug_errno(r, "Error converting pgscan value to uint64_t: %m");
        }

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
        _cleanup_(oomd_cgroup_context_unrefp) OomdCGroupContext *curr_ctx = NULL;
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
