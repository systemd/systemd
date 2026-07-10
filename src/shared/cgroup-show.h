/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int show_cgroup_by_path(const char *path, const char *prefix, size_t n_columns, OutputFlags flags);
int show_cgroup(const char *path, const char *prefix, size_t n_columns, OutputFlags flags);
int show_cgroup_and_extra(
                const char *path,
                const char *prefix,
                size_t n_columns,
                const pid_t extra_pids[],
                size_t n_extra_pids,
                OutputFlags flags);

int show_cgroup_get_unit_path_and_warn(
                sd_bus *bus,
                const char *unit,
                char **ret);
int show_cgroup_get_path_and_warn(
                const char *machine,
                const char *prefix,
                char **ret);
