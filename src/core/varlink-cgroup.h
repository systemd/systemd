/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cgroup.h"
#include "core-forward.h"

int unit_cgroup_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int unit_cgroup_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);

/* Parsed CGroup context fields of a StartTransient call. Numeric fields carry a *_set flag since the
 * JSON value alone cannot distinguish "absent" from "explicitly set to 0"; accounting bools are
 * tristates (-1 = absent). Set-up/tear-down via transient_cgroup_context_parameters_init(); nothing
 * is allocated (strings are borrowed from the JSON variant), so no done() counterpart exists. */
typedef struct TransientCGroupContextParameters {
        bool present;

        const char *slice;

        bool cpu_weight_set;
        uint64_t cpu_weight;
        bool startup_cpu_weight_set;
        uint64_t startup_cpu_weight;
        bool cpu_quota_per_sec_usec_set;
        uint64_t cpu_quota_per_sec_usec;
        bool cpu_quota_period_usec_set;
        uint64_t cpu_quota_period_usec;

        int memory_accounting;
        bool memory_min_set;
        uint64_t memory_min;
        bool memory_low_set;
        uint64_t memory_low;
        bool startup_memory_low_set;
        uint64_t startup_memory_low;
        bool memory_high_set;
        uint64_t memory_high;
        bool startup_memory_high_set;
        uint64_t startup_memory_high;
        bool memory_max_set;
        uint64_t memory_max;
        bool startup_memory_max_set;
        uint64_t startup_memory_max;
        bool memory_swap_max_set;
        uint64_t memory_swap_max;
        bool startup_memory_swap_max_set;
        uint64_t startup_memory_swap_max;
        bool memory_zswap_max_set;
        uint64_t memory_zswap_max;
        bool startup_memory_zswap_max_set;
        uint64_t startup_memory_zswap_max;
        int memory_zswap_writeback;

        int tasks_accounting;
        bool tasks_max_set;
        CGroupTasksMax tasks_max;

        int io_accounting;
        bool io_weight_set;
        uint64_t io_weight;
        bool startup_io_weight_set;
        uint64_t startup_io_weight;
} TransientCGroupContextParameters;

void transient_cgroup_context_parameters_init(TransientCGroupContextParameters *p);
int transient_cgroup_context_dispatch(sd_json_variant *variant, TransientCGroupContextParameters *p, const char **reterr_bad_field);
int transient_cgroup_context_apply_properties(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p, const char **reterr_field);
