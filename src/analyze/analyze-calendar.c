/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-calendar.h"
#include "calendarspec.h"
#include "format-table.h"
#include "terminal-util.h"

static int test_calendar_one(usec_t n, const char *p) {
        _cleanup_(calendar_spec_freep) CalendarSpec *spec = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *t = NULL;
        TableCell *cell;
        int r;

        r = calendar_spec_from_string(p, &spec);
        if (r < 0) {
                log_error_errno(r, "Failed to parse calendar specification '%s': %m", p);
                time_parsing_hint(p, /* calendar= */ false, /* timestamp= */ true, /* timespan= */ true);
                return r;
        }

        r = calendar_spec_to_string(spec, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to format calendar specification '%s': %m", p);

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

        if (!streq(t, p)) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Original form",
                                   TABLE_STRING, p);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_add_many(table,
                           TABLE_FIELD, "Normalized form",
                           TABLE_STRING, t);
        if (r < 0)
                return table_log_add_error(r);

        for (unsigned i = 0; i < arg_iterations; i++) {
                usec_t next;

                r = calendar_spec_next_usec(spec, n, &next);
                if (r == -ENOENT) {
                        if (i == 0) {
                                r = table_add_many(table,
                                                   TABLE_FIELD, "Next elapse",
                                                   TABLE_STRING, "never",
                                                   TABLE_SET_COLOR, ansi_highlight_yellow());
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to determine next elapse for '%s': %m", p);

                if (i == 0) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Next elapse",
                                           TABLE_TIMESTAMP, next,
                                           TABLE_SET_COLOR, ansi_highlight_blue());
                        if (r < 0)
                                return table_log_add_error(r);
                } else {
                        int k = DECIMAL_STR_WIDTH(i + 1);

                        if (k < 8)
                                k = 8 - k;
                        else
                                k = 0;

                        r = table_add_cell_stringf_full(table, NULL, TABLE_FIELD, "Iteration #%u", i+1);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = table_add_many(table,
                                           TABLE_TIMESTAMP, next,
                                           TABLE_SET_COLOR, ansi_highlight_blue());
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (!in_utc_timezone()) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "(in UTC)",
                                           TABLE_TIMESTAMP_UTC, next);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_FIELD, "From now",
                                   TABLE_TIMESTAMP_RELATIVE, next);
                if (r < 0)
                        return table_log_add_error(r);

                n = next;
        }

        return table_print(table, NULL);
}

int verb_calendar(int argc, char *argv[], void *userdata) {
        int r = 0;
        usec_t n;

        if (arg_base_time != USEC_INFINITY)
                n = arg_base_time;
        else
                n = now(CLOCK_REALTIME); /* We want to use the same "base" for all expressions */

        STRV_FOREACH(p, strv_skip(argv, 1)) {
                RET_GATHER(r, test_calendar_one(n, *p));

                if (p[1])
                        putchar('\n');
        }

        return r;
}
