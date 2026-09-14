/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "metrics.h"

#define METRIC_IO_SYSTEMD_CGROUP_PREFIX "io.systemd.CGroup."

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

/* Exported for test-report-cgroup.c. mf[] must be the PressureAvg10 and PressureStallSeconds families,
 * in that order, and cgroup_fs_path is the path to the cgroup in the file system. */
int report_cgroup_pressure_send(const MetricFamily mf[static 2], sd_varlink *link, const char *cgroup_fs_path, const char *unit);
