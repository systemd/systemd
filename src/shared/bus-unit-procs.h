/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int unit_show_processes(sd_bus *bus, const char *unit, const char *cgroup_path, const char *prefix, unsigned n_columns, OutputFlags flags, sd_bus_error *reterr_error);
