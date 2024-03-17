/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-table.h"
#include "vmspawn-settings.h"

static const char *const console_mode_table[_CONSOLE_MODE_MAX] = {
        [CONSOLE_INTERACTIVE] = "interactive",
        [CONSOLE_READ_ONLY]   = "read-only",
        [CONSOLE_NATIVE]      = "native",
        [CONSOLE_GUI]         = "gui",
};

DEFINE_STRING_TABLE_LOOKUP(console_mode, ConsoleMode);
