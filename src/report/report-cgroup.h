/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct MetricFamily MetricFamily;

#define METRIC_IO_SYSTEMD_CGROUP_PREFIX "io.systemd.CGroup."

int report_cgroup_pressure_send(const MetricFamily *mf, sd_varlink *link, const char *cgroup_fs_path, const char *unit);
