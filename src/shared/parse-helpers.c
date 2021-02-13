/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-helpers.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"

int parse_arg_signal(const char *s, int *ret) {
        assert(s);
        assert(ret);

        if (streq(s, "help")) {
                DUMP_STRING_TABLE(signal, int, _NSIG);
                return 0;
        }

        int r = signal_from_string(s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse signal string \"%s\".", s);

        *ret = r;
        return 1; /* work to do */
}
