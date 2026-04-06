/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define METRIC_IO_SYSTEMD_CGROUP_PREFIX "io.systemd.CGroup."

typedef struct UnitCGroupInfo UnitCGroupInfo;

typedef struct CGroupMetricsContext {
        UnitCGroupInfo **units;
        size_t n_units;
        bool cache_populated;
} CGroupMetricsContext;

CGroupMetricsContext *cgroup_metrics_context_free(CGroupMetricsContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(CGroupMetricsContext*, cgroup_metrics_context_free);

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
