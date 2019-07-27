/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "sd-bus.h"

#include "logs-show.h"
#include "output-mode.h"

int show_cgroup_by_path(const char *path, const char *prefix, size_t n_columns, OutputFlags flags);
int show_cgroup(const char *controller, const char *path, const char *prefix, size_t n_columns, OutputFlags flags);

int show_cgroup_and_extra(const char *controller, const char *path, const char *prefix, size_t n_columns, const pid_t extra_pids[], unsigned n_extra_pids, OutputFlags flags);

int show_cgroup_get_unit_path_and_warn(
                sd_bus *bus,
                const char *unit,
                char **ret);
int show_cgroup_get_path_and_warn(
                const char *machine,
                const char *prefix,
                char **ret);
