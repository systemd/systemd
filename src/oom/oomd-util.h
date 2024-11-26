/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "cgroup-util.h"
#include "hashmap.h"
#include "psi-util.h"

#define DUMP_ON_KILL_COUNT 10u
#define GROWING_SIZE_PERCENTILE 80

extern const struct hash_ops oomd_cgroup_ctx_hash_ops;

typedef struct OomdCGroupContext OomdCGroupContext;
typedef struct OomdSystemContext OomdSystemContext;

typedef int (oomd_compare_t)(OomdCGroupContext * const *, OomdCGroupContext * const *);

struct OomdCGroupContext {
        char *path;

        ResourcePressure memory_pressure;

        uint64_t current_memory_usage;

        uint64_t memory_min;
        uint64_t memory_low;
        uint64_t swap_usage;

        uint64_t last_pgscan;
        uint64_t pgscan;

        ManagedOOMPreference preference;

        /* These are only used for acting on high memory pressure. */
        loadavg_t mem_pressure_limit;
        usec_t mem_pressure_limit_hit_start;
        usec_t last_had_mem_reclaim;
        usec_t mem_pressure_duration_usec;
};

struct OomdSystemContext {
        uint64_t mem_total;
        uint64_t mem_used;
        uint64_t swap_total;
        uint64_t swap_used;
};

OomdCGroupContext *oomd_cgroup_context_free(OomdCGroupContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(OomdCGroupContext*, oomd_cgroup_context_free);

/* All hashmaps used with these functions are expected to be of the form
 * key: cgroup paths -> value: OomdCGroupContext. */

/* Scans all the OomdCGroupContexts in `h` and returns 1 and a set of pointers to those OomdCGroupContexts in `ret`
 * if any of them have exceeded their supplied memory pressure limits for the `ctx->mem_pressure_duration_usec` length of time.
 * `mem_pressure_limit_hit_start` is updated accordingly for the first time the limit is exceeded, and when it returns
 * below the limit.
 * Returns 0 and sets `ret` to an empty set if no entries exceeded limits for `ctx->mem_pressure_duration_usec`.
 * Returns -ENOMEM for allocation errors. */
int oomd_pressure_above(Hashmap *h, Set **ret);

/* Returns true if the amount of memory available (see proc(5)) is below the permyriad of memory specified by `threshold_permyriad`. */
bool oomd_mem_available_below(const OomdSystemContext *ctx, int threshold_permyriad);

/* Returns true if the amount of swap free is below the permyriad of swap specified by `threshold_permyriad`. */
bool oomd_swap_free_below(const OomdSystemContext *ctx, int threshold_permyriad);

/* Returns pgscan - last_pgscan, accounting for corner cases. */
uint64_t oomd_pgscan_rate(const OomdCGroupContext *c);

/* The compare functions will sort from largest to smallest, putting all the contexts with "avoid" at the end
 * (after the smallest values). */
static inline int compare_pgscan_rate_and_memory_usage(OomdCGroupContext * const *c1, OomdCGroupContext * const *c2) {
        uint64_t diff1, diff2;
        int r;

        assert(c1);
        assert(c2);

        r = CMP((*c1)->preference, (*c2)->preference);
        if (r != 0)
                return r;

        diff1 = oomd_pgscan_rate(*c1);
        diff2 = oomd_pgscan_rate(*c2);
        r = CMP(diff2, diff1);
        if (r != 0)
                return r;

        return CMP((*c2)->current_memory_usage, (*c1)->current_memory_usage);
}

static inline int compare_swap_usage(OomdCGroupContext * const *c1, OomdCGroupContext * const *c2) {
        int r;

        assert(c1);
        assert(c2);

        r = CMP((*c1)->preference, (*c2)->preference);
        if (r != 0)
                return r;

        return CMP((*c2)->swap_usage, (*c1)->swap_usage);
}

/* Get an array of OomdCGroupContexts from `h`, qsorted from largest to smallest values according to `compare_func`.
 * If `prefix` is not NULL, only include OomdCGroupContexts whose paths start with prefix. Otherwise all paths are sorted.
 * Returns the number of sorted items; negative on error. */
int oomd_sort_cgroup_contexts(Hashmap *h, oomd_compare_t compare_func, const char *prefix, OomdCGroupContext ***ret);

/* If the cgroup is owned by root, or the cgroups represented by `ctx` and
 * `prefix` are owned by the same user, then set `ctx->preference` using the
 * `user.oomd_avoid` and `user.oomd_omit` xattrs. Otherwise, set
 * `ctx->preference` to MANAGED_OOM_PREFERENCE_NONE.
 *
 * If `prefix` is NULL or the empty string, it is treated as root. If `prefix`
 * does not specify an ancestor cgroup of `ctx`, -EINVAL is returned. Returns
 * negative on all other errors. */
int oomd_fetch_cgroup_oom_preference(OomdCGroupContext *ctx, const char *prefix);

/* Returns a negative value on error, 0 if no processes were killed, or 1 if processes were killed. */
int oomd_cgroup_kill(const char *path, bool recurse, bool dry_run);

/* The following oomd_kill_by_* functions return 1 if processes were killed, or negative otherwise. */
/* If `prefix` is supplied, only cgroups whose paths start with `prefix` are eligible candidates. Otherwise,
 * everything in `h` is a candidate.
 * Returns the killed cgroup in ret_selected. */
int oomd_kill_by_pgscan_rate(Hashmap *h, const char *prefix, bool dry_run, char **ret_selected);
int oomd_kill_by_swap_usage(Hashmap *h, uint64_t threshold_usage, bool dry_run, char **ret_selected);

int oomd_cgroup_context_acquire(const char *path, OomdCGroupContext **ret);
int oomd_system_context_acquire(const char *proc_swaps_path, OomdSystemContext *ret);

/* Get the OomdCGroupContext of `path` and insert it into `new_h`. The key for the inserted context will be `path`.
 *
 * `old_h` is used to get data used to calculate prior interval information. `old_h` can be NULL in which case there
 * was no prior data to reference. */
int oomd_insert_cgroup_context(Hashmap *old_h, Hashmap *new_h, const char *path);

/* Update each OomdCGroupContext in `curr_h` with prior interval information from `old_h`. */
void oomd_update_cgroup_contexts_between_hashmaps(Hashmap *old_h, Hashmap *curr_h);

void oomd_dump_swap_cgroup_context(const OomdCGroupContext *ctx, FILE *f, const char *prefix);
void oomd_dump_memory_pressure_cgroup_context(const OomdCGroupContext *ctx, FILE *f, const char *prefix);
void oomd_dump_system_context(const OomdSystemContext *ctx, FILE *f, const char *prefix);
