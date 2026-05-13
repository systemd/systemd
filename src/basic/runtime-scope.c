/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "runtime-scope.h"
#include "string-table.h"

static const char* const runtime_scope_table[_RUNTIME_SCOPE_MAX] = {
        [RUNTIME_SCOPE_SYSTEM] = "system",
        [RUNTIME_SCOPE_USER]   = "user",
        [RUNTIME_SCOPE_GLOBAL] = "global",
};

DEFINE_STRING_TABLE_LOOKUP(runtime_scope, RuntimeScope);

static const char* const runtime_scope_cmdline_option_table[_RUNTIME_SCOPE_MAX] = {
        [RUNTIME_SCOPE_SYSTEM] = "--system",
        [RUNTIME_SCOPE_USER]   = "--user",
        [RUNTIME_SCOPE_GLOBAL] = "--global",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(runtime_scope_cmdline_option, RuntimeScope);
