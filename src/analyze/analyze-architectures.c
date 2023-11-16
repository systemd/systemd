/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-architectures.h"
#include "format-table.h"

static int add_arch(Table *t, Architecture a) {
        const char *c, *color;
        int r;

        assert(t);

        if (a == native_architecture()) {
                c = "native";
                color = ANSI_HIGHLIGHT_GREEN;
        } else if (a == uname_architecture()) {
                c = "uname";
                color = ANSI_HIGHLIGHT;
#ifdef ARCHITECTURE_SECONDARY
        } else if (a == ARCHITECTURE_SECONDARY) {
                c = "secondary";
                color = NULL;
#endif
        } else {
                c = "foreign";
                color = ANSI_GREY;
        }

        r = table_add_many(t,
                           TABLE_INT, (int) a,
                           TABLE_STRING, architecture_to_string(a),
                           TABLE_STRING, c,
                           TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_architectures(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        table = table_new("id", "name", "support");
        if (!table)
                return log_oom();

        (void) table_hide_column_from_display(table, (size_t) 0);

        if (strv_isempty(strv_skip(argv, 1)))
                for (Architecture a = 0; a < _ARCHITECTURE_MAX; a++) {
                        r = add_arch(table, a);
                        if (r < 0)
                                return r;
                }
        else {
                STRV_FOREACH(as, strv_skip(argv, 1)) {
                        Architecture a;

                        if (streq(*as, "native"))
                                a = native_architecture();
                        else if (streq(*as, "uname"))
                                a = uname_architecture();
                        else if (streq(*as, "secondary")) {
#ifdef ARCHITECTURE_SECONDARY
                                a = ARCHITECTURE_SECONDARY;
#else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No secondary architecture.");
#endif
                        } else
                                a = architecture_from_string(*as);
                        if (a < 0)
                                return log_error_errno(a, "Architecture \"%s\" not known.", *as);

                        r = add_arch(table, a);
                        if (r < 0)
                                return r;
                }

                (void) table_set_sort(table, (size_t) 0);
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        return EXIT_SUCCESS;
}
