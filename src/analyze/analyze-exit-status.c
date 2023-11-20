/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-exit-status.h"
#include "exit-status.h"
#include "format-table.h"

int verb_exit_status(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        table = table_new("name", "status", "class");
        if (!table)
                return log_oom();

        r = table_set_align_percent(table, table_get_cell(table, 0, 1), 100);
        if (r < 0)
                return log_error_errno(r, "Failed to right-align status: %m");

        if (strv_isempty(strv_skip(argv, 1)))
                for (size_t i = 0; i < ELEMENTSOF(exit_status_mappings); i++) {
                        if (!exit_status_mappings[i].name)
                                continue;

                        r = table_add_many(table,
                                           TABLE_STRING, exit_status_mappings[i].name,
                                           TABLE_INT, (int) i,
                                           TABLE_STRING, exit_status_class(i));
                        if (r < 0)
                                return table_log_add_error(r);
                }
        else
                for (int i = 1; i < argc; i++) {
                        int status;

                        status = exit_status_from_string(argv[i]);
                        if (status < 0)
                                return log_error_errno(status, "Invalid exit status \"%s\".", argv[i]);

                        assert(status >= 0 && (size_t) status < ELEMENTSOF(exit_status_mappings));
                        r = table_add_many(table,
                                           TABLE_STRING, exit_status_mappings[status].name ?: "-",
                                           TABLE_INT, status,
                                           TABLE_STRING, exit_status_class(status) ?: "-");
                        if (r < 0)
                                return table_log_add_error(r);
                }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        return EXIT_SUCCESS;
}
