/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-blame.h"
#include "analyze-time-data.h"
#include "format-table.h"

int verb_blame(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        n = acquire_time_data(bus, /* require_finished = */ false, &times);
        if (n <= 0)
                return n;

        table = table_new("time", "unit");
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

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return r;

        r = table_set_reverse(table, 0, true);
        if (r < 0)
                return r;

        for (UnitTimes *u = times; u->has_data; u++) {
                if (u->time <= 0)
                        continue;

                r = table_add_many(table,
                                   TABLE_TIMESPAN_MSEC, u->time,
                                   TABLE_STRING, u->name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        pager_open(arg_pager_flags);

        r = table_print(table, NULL);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
