/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-hwdb.h"

bool hwdb_should_reload(sd_hwdb *hwdb);
int hwdb_update(const char *root, const char *hwdb_bin_dir, bool strict, bool compat);
int hwdb_query(const char *modalias, const char *root);
