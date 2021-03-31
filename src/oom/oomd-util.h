/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "cgroup-util.h"
#include "hashmap.h"
#include "psi-util.h"

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

        /* These are only used by oomd_pressure_above for acting on high memory pressure. */
        loadavg_t mem_pressure_limit;
        usec_t mem_pressure_duration_usec;
        usec_t last_hit_mem_pressure_limit;
};

struct OomdSystemContext {
        uint64_t swap_total;
        uint64_t swap_used;
};

OomdCGroupContext *oomd_cgroup_context_free(OomdCGroupContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(OomdCGroupContext*, oomd_cgroup_context_free);

/* All hashmaps used with these functions are expected to be of the form
 * key: cgroup paths -> value: OomdCGroupContext. */

/* Scans all the OomdCGroupContexts in `h` and returns 1 and a set of pointers to those OomdCGroupContexts in `ret`
 * if any of them have exceeded their supplied memory pressure limits for the `duration` length of time.
 * `last_hit_mem_pressure_limit` is updated accordingly for each entry when the limit is exceeded, and when it returns
 * below the limit.
 * Returns 0 and sets `ret` to an empty set if no entries exceeded limits for `duration`.
 * Returns -ENOMEM for allocation errors. */
int oomd_pressure_above(Hashmap *h, usec_t duration, Set **ret);

/* Sum up current OomdCGroupContexts' pgscan values and last interval's pgscan values in `h`. Returns true if the
 * current sum is higher than the last interval's sum (there was some reclaim activity). */
bool oomd_memory_reclaim(Hashmap *h);

/* Returns true if the amount of swap free is below the permyriad of swap specified by `threshold_permyriad`. */
bool oomd_swap_free_below(const OomdSystemContext *ctx, int threshold_permyriad);

/* The compare functions will sort from largest to smallest, putting all the contexts with "avoid" at the end
 * (after the smallest values). */
static inline int compare_pgscan_rate_and_memory_usage(OomdCGroupContext * const *c1, OomdCGroupContext * const *c2) {
        uint64_t last1, last2;
        int r;

        assert(c1);
        assert(c2);

        r = CMP((*c1)->preference, (*c2)->preference);
        if (r != 0)
                return r;

        /* If last_pgscan > pgscan, assume the cgroup was recreated and reset last_pgscan to zero. */
        last2 = (*c2)->last_pgscan;
        if ((*c2)->last_pgscan > (*c2)->pgscan) {
                log_info("Last pgscan %" PRIu64 "greater than current pgscan %" PRIu64 "for %s. Using last pgscan of zero.",
                                (*c2)->last_pgscan, (*c2)->pgscan, (*c2)->path);
                last2 = 0;
        }

        last1 = (*c1)->last_pgscan;
        if ((*c1)->last_pgscan > (*c1)->pgscan) {
                log_info("Last pgscan %" PRIu64 "greater than current pgscan %" PRIu64 "for %s. Using last pgscan of zero.",
                                (*c1)->last_pgscan, (*c1)->pgscan, (*c1)->path);
                last1 = 0;
        }

        r = CMP((*c2)->pgscan - last2, (*c1)->pgscan - last1);
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

/* Returns a negative value on error, 0 if no processes were killed, or 1 if processes were killed. */
int oomd_cgroup_kill(const char *path, bool recurse, bool dry_run);

/* The following oomd_kill_by_* functions return 1 if processes were killed, or negative otherwise. */
/* If `prefix` is supplied, only cgroups whose paths start with `prefix` are eligible candidates. Otherwise,
 * everything in `h` is a candidate.
 * Returns the killed cgroup in ret_selected. */
int oomd_kill_by_pgscan_rate(Hashmap *h, const char *prefix, bool dry_run, char **ret_selected);
int oomd_kill_by_swap_usage(Hashmap *h, bool dry_run, char **ret_selected);

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
