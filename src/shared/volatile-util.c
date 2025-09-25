/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "proc-cmdline.h"
#include "string-table.h"
#include "string-util.h"
#include "volatile-util.h"

int query_volatile_mode(VolatileMode *ret) {
        _cleanup_free_ char *mode = NULL;
        int r;

        r = proc_cmdline_get_key("systemd.volatile", PROC_CMDLINE_VALUE_OPTIONAL, &mode);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = VOLATILE_NO;
                return 0;
        }

        if (mode) {
                VolatileMode m;

                m = volatile_mode_from_string(mode);
                if (m < 0)
                        return m;

                *ret = m;
        } else
                *ret = VOLATILE_YES;

        return 1;
}

static const char* const volatile_mode_table[_VOLATILE_MODE_MAX] = {
        [VOLATILE_NO] = "no",
        [VOLATILE_YES] = "yes",
        [VOLATILE_STATE] = "state",
        [VOLATILE_OVERLAY_ROOT] = "overlay-root",
        [VOLATILE_OVERLAY_USR] = "overlay-usr",
};

const char* volatile_mode_to_string(VolatileMode i) {
        return string_table_lookup_to_string(volatile_mode_table, ELEMENTSOF(volatile_mode_table), i);
}

VolatileMode volatile_mode_from_string(const char *s) {
        /* Handle backward compatibility: "overlay" maps to VOLATILE_OVERLAY_ROOT */
        if (streq_ptr(s, "overlay"))
                return VOLATILE_OVERLAY_ROOT;

        return (VolatileMode) string_table_lookup_from_string_with_boolean(volatile_mode_table, ELEMENTSOF(volatile_mode_table), s, VOLATILE_YES);
}
