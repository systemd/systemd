/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-timespan.h"
#include "ansi-color.h"
#include "format-table.h"
#include "glyph-util.h"
#include "log.h"
#include "strv.h"
#include "time-util.h"

int verb_timespan(int argc, char *argv[], void *userdata) {
        STRV_FOREACH(input_timespan, strv_skip(argv, 1)) {
                _cleanup_(table_unrefp) Table *table = NULL;
                usec_t output_usecs;
                TableCell *cell;
                int r;

                r = parse_time(*input_timespan, &output_usecs, USEC_PER_SEC);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse time span '%s': %m", *input_timespan);
                        time_parsing_hint(*input_timespan, /* calendar= */ true, /* timestamp= */ true, /* timespan= */ false);
                        return r;
                }

                table = table_new_vertical();
                if (!table)
                        return log_oom();

                assert_se(cell = table_get_cell(table, 0, 0));
                r = table_set_ellipsize_percent(table, cell, 100);
                if (r < 0)
                        return r;

                assert_se(cell = table_get_cell(table, 0, 1));
                r = table_set_ellipsize_percent(table, cell, 100);
                if (r < 0)
                        return r;

                r = table_add_many(table,
                                   TABLE_FIELD, "Original",
                                   TABLE_STRING, *input_timespan);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf_full(table, NULL, TABLE_FIELD, "%ss", glyph(GLYPH_MU));
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_UINT64, output_usecs,
                                   TABLE_FIELD, "Human",
                                   TABLE_TIMESPAN, output_usecs,
                                   TABLE_SET_COLOR, ansi_highlight());
                if (r < 0)
                        return table_log_add_error(r);

                r = table_print(table, NULL);
                if (r < 0)
                        return r;

                if (input_timespan[1])
                        putchar('\n');
        }

        return 0;
}
