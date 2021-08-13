/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "unit-file.h"

typedef enum AnalyzeSecurityFlags {
        ANALYZE_SECURITY_SHORT                          = 1 << 0,
        ANALYZE_SECURITY_ONLY_LOADED                    = 1 << 1,
        ANALYZE_SECURITY_ONLY_LONG_RUNNING              = 1 << 2,
        ANALYZE_SECURITY_ERROR_IF_EXPOSURE_ABOVE_MEDIUM = 1 << 3,
} AnalyzeSecurityFlags;

int analyze_security(sd_bus *bus, char **units, UnitFileScope scope, bool check_man, bool run_generators, bool offline, const char *root, AnalyzeSecurityFlags flags);
