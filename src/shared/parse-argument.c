/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-argument.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"

int parse_signal_argument(const char *s, int *ret) {
        int r;

        assert(s);
        assert(ret);

        if (streq(s, "help")) {
                DUMP_STRING_TABLE(signal, int, _NSIG);
                return 0;
        }

        r = signal_from_string(s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse signal string \"%s\".", s);

        *ret = r;
        return 1; /* work to do */
}
