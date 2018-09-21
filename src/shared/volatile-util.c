/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "string-table.h"
#include "string-util.h"
#include "volatile-util.h"

int query_volatile_mode(VolatileMode *ret) {
        _cleanup_free_ char *mode = NULL;
        VolatileMode m = VOLATILE_NO;
        int r;

        r = proc_cmdline_get_key("systemd.volatile", PROC_CMDLINE_VALUE_OPTIONAL, &mode);
        if (r < 0)
                return r;
        if (r == 0)
                goto finish;

        if (mode) {
                m = volatile_mode_from_string(mode);
                if (m < 0)
                        return -EINVAL;
        } else
                m = VOLATILE_YES;

        r = 1;

finish:
        *ret = m;
        return r;
}

static const char* const volatile_mode_table[_VOLATILE_MODE_MAX] = {
        [VOLATILE_NO] = "no",
        [VOLATILE_YES] = "yes",
        [VOLATILE_STATE] = "state",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(volatile_mode, VolatileMode, VOLATILE_YES);
