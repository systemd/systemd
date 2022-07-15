/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-timestamp.h"
#include "format-table.h"
#include "terminal-util.h"

static int test_timestamp_one(const char *p) {
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        usec_t usec;
        int r;

        r = parse_timestamp(p, &usec);
        if (r < 0) {
                log_error_errno(r, "Failed to parse \"%s\": %m", p);
                time_parsing_hint(p, /* calendar= */ true, /* timestamp= */ false, /* timespan= */ true);
                return r;
        }

        table = table_new("name", "value");
        if (!table)
                return log_oom();

        table_set_header(table, false);

        assert_se(cell = table_get_cell(table, 0, 0));
        r = table_set_ellipsize_percent(table, cell, 100);
        if (r < 0)
                return r;

        r = table_set_align_percent(table, cell, 100);
        if (r < 0)
                return r;

        assert_se(cell = table_get_cell(table, 0, 1));
        r = table_set_ellipsize_percent(table, cell, 100);
        if (r < 0)
                return r;

        r = table_add_many(table,
                           TABLE_STRING, "Original form:",
                           TABLE_STRING, p,
                           TABLE_STRING, "Normalized form:",
                           TABLE_TIMESTAMP, usec,
                           TABLE_SET_COLOR, ansi_highlight_blue());
        if (r < 0)
                return table_log_add_error(r);

        if (!in_utc_timezone()) {
                r = table_add_many(table,
                                   TABLE_STRING, "(in UTC):",
                                   TABLE_TIMESTAMP_UTC, usec);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_add_cell(table, NULL, TABLE_STRING, "UNIX seconds:");
        if (r < 0)
                return table_log_add_error(r);

        if (usec % USEC_PER_SEC == 0)
                r = table_add_cell_stringf(table, NULL, "@%"PRI_USEC,
                                           usec / USEC_PER_SEC);
        else
                r = table_add_cell_stringf(table, NULL, "@%"PRI_USEC".%06"PRI_USEC"",
                                           usec / USEC_PER_SEC,
                                           usec % USEC_PER_SEC);
        if (r < 0)
                return r;

        r = table_add_many(table,
                           TABLE_STRING, "From now:",
                           TABLE_TIMESTAMP_RELATIVE, usec);
        if (r < 0)
                return table_log_add_error(r);

        return table_print(table, NULL);
}

int verb_timestamp(int argc, char *argv[], void *userdata) {
        int r = 0;

        STRV_FOREACH(p, strv_skip(argv, 1)) {
                int k;

                k = test_timestamp_one(*p);
                if (r == 0 && k < 0)
                        r = k;

                if (p[1])
                        putchar('\n');
        }

        return r;
}
