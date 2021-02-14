/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "parse-argument.h"
#include "path-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"

/* All functions in this file emit warnigs. */

int parse_path_argument(const char *path, bool suppress_root, char **arg) {
        char *p;
        int r;

        /*
         * This function is intended to be used in command line parsers, to handle paths that are passed
         * in. It makes the path absolute, and reduces it to NULL if omitted or root (the latter optionally).
         *
         * NOTE THAT THIS WILL FREE THE PREVIOUS ARGUMENT POINTER ON SUCCESS!
         * Hence, do not pass in uninitialized pointers.
         */

        if (isempty(path)) {
                *arg = mfree(*arg);
                return 0;
        }

        r = path_make_absolute_cwd(path, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to parse path \"%s\" and make it absolute: %m", path);

        path_simplify(p, false);
        if (suppress_root && empty_or_root(p))
                p = mfree(p);

        return free_and_replace(*arg, p);
}

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
                        r = table_add_many(
                                        table,
                                        TABLE_INT, i,
                                        TABLE_SIGNAL, i);
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
