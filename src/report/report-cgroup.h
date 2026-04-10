/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define METRIC_IO_SYSTEMD_CGROUP_PREFIX "io.systemd.CGroup."

typedef struct CGroupInfo CGroupInfo;

typedef struct CGroupContext {
        CGroupInfo **cgroups;
        size_t n_cgroups;
        bool cache_populated;
} CGroupContext;

CGroupContext *cgroup_context_free(CGroupContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(CGroupContext*, cgroup_context_free);

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
