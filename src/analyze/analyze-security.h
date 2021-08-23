/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "json.h"
#include "unit-file.h"

typedef enum AnalyzeSecurityFlags {
        ANALYZE_SECURITY_SHORT             = 1 << 0,
        ANALYZE_SECURITY_ONLY_LOADED       = 1 << 1,
        ANALYZE_SECURITY_ONLY_LONG_RUNNING = 1 << 2,
} AnalyzeSecurityFlags;

int analyze_security(sd_bus *bus,
                     char **units,
                     JsonVariant *policy,
                     UnitFileScope scope,
                     bool check_man,
                     bool run_generators,
                     bool offline,
                     unsigned threshold,
                     const char *root,
                     AnalyzeSecurityFlags flags);
