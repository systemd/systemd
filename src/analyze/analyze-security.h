/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

typedef enum AnalyzeSecurityFlags
{
        ANALYZE_SECURITY_SHORT = 1 << 0,
        ANALYZE_SECURITY_ONLY_LOADED = 1 << 1,
        ANALYZE_SECURITY_ONLY_LONG_RUNNING = 1 << 2,
} AnalyzeSecurityFlags;

int analyze_security(sd_bus *bus, char **units, AnalyzeSecurityFlags flags);
