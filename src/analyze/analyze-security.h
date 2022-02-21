/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum AnalyzeSecurityFlags {
        ANALYZE_SECURITY_SHORT             = 1 << 0,
        ANALYZE_SECURITY_ONLY_LOADED       = 1 << 1,
        ANALYZE_SECURITY_ONLY_LONG_RUNNING = 1 << 2,
} AnalyzeSecurityFlags;

int verb_security(int argc, char *argv[], void *userdata);
