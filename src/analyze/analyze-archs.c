/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-archs.h"
#include "format-table.h"

static int add_arch(Table *t, Architecture a) {
        const char *c = NULL, *color = NULL;
        int r;

        if (a == native_architecture()) {
                c = "native";
                color = ANSI_HIGHLIGHT_GREEN;
        } else if (a == uname_architecture()) {
                c = "uname";
                color = ANSI_HIGHLIGHT_WHITE;
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

int verb_archs(int argc, char *argv[], void *userdata) {
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
                for (int i = 1; i < argc; i++) {
                        Architecture a;

                        if (streq(argv[i], "native"))
                                a = native_architecture();
                        else if (streq(argv[i], "uname"))
                                a = uname_architecture();
                        else if (streq(argv[i], "secondary")) {
#ifdef ARCHITECTURE_SECONDARY
                                a = ARCHITECTURE_SECONDARY;
#else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No secondary architecture.");
#endif
                        } else
                                a = architecture_from_string(argv[i]);
                        if (a < 0)
                                return log_error_errno(a, "Architecture \"%s\" not known.", argv[i]);

                        r = add_arch(table, a);
                        if (r < 0)
                                return r;
                }

                 (void) table_set_sort(table, (size_t) 0);
        }

        pager_open(arg_pager_flags);

        r = table_print(table, NULL);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
