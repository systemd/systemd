/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/io_uring.h>
#include <stdlib.h>

#include "analyze.h"
#include "analyze-io-uring-filter.h"
#include "format-table.h"
#include "io-uring-filter.h"
#include "log.h"
#include "nulstr-util.h"
#include "strv.h"

static int add_op(Table *t, int op) {
        _cleanup_strv_free_ char **syscalls = NULL;
        const char *s;
        int r;

        assert(t);

        s = io_uring_op_syscalls_to_string(op);
        if (s) {
                syscalls = strv_split_nulstr(s);
                if (!syscalls)
                        return log_oom();
        }

        r = table_add_many(t,
                           TABLE_INT, op,
                           TABLE_STRING, io_uring_op_to_string(op),
                           TABLE_STRV_WRAPPED, syscalls);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_io_uring_filter(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        table = table_new("opcode", "name", "syscalls");
        if (!table)
                return log_oom();

        (void) table_hide_column_from_display(table, (size_t) 0);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        char **args = strv_skip(argv, 1);
        if (args) {
                STRV_FOREACH(arg, args) {
                        int op;

                        op = io_uring_op_from_string(*arg);
                        if (op < 0)
                                return log_error_errno(op, "io_uring operation \"%s\" not known.", *arg);

                        r = add_op(table, op);
                        if (r < 0)
                                return r;
                }

                (void) table_set_sort(table, (size_t) 0);
        } else
                for (int op = 0; op < IORING_OP_LAST; op++) {
                        r = add_op(table, op);
                        if (r < 0)
                                return r;
                }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
