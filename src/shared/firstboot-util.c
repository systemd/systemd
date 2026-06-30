/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "firstboot-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "string-table.h"

static const char* const firstboot_mode_table[_FIRSTBOOT_MODE_MAX] = {
        [FIRSTBOOT_OFF]         = "no",
        [FIRSTBOOT_INTERACTIVE] = "yes",
        [FIRSTBOOT_HEADLESS]    = "headless",
};

assert_cc(FIRSTBOOT_OFF == 0);

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(firstboot_mode, FirstBootMode, FIRSTBOOT_INTERACTIVE);

int firstboot_mode_from_cmdline(FirstBootMode *ret) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key("systemd.firstboot", PROC_CMDLINE_VALUE_OPTIONAL, &value);
        if (r < 0)
                return r;
        if (r == 0) { /* not specified at all */
                *ret = FIRSTBOOT_INTERACTIVE;
                return 0;
        }
        if (!value) { /* key without parameter, i.e. bare "systemd.firstboot" */
                *ret = FIRSTBOOT_INTERACTIVE;
                return 1;
        }

        FirstBootMode m = firstboot_mode_from_string(value);
        if (m < 0)
                return log_debug_errno(m, "Invalid systemd.firstboot= value '%s'.", value);

        *ret = m;
        return 1;
}
