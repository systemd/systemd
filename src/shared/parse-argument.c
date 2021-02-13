/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "parse-argument.h"
#include "signal-util.h"
#include "stdio-util.h"
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

        if (streq(s, "list")) {
                _cleanup_(table_unrefp) Table *table = NULL;

                table = table_new("signal", "name");
                if (!table)
                        return log_oom();

                for (int i = 1; i < _NSIG; i++) {
                        char n[STRLEN("SIGRTMIN+") + DECIMAL_STR_MAX(int)];

                        xsprintf(n, "SIG%s", signal_to_string(i));

                        r = table_add_many(
                                        table,
                                        TABLE_INT, i,
                                        TABLE_STRING, n);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);

                return 0;
        }

        r = signal_from_string(s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse signal string \"%s\".", s);

        *ret = r;
        return 1; /* work to do */
}
