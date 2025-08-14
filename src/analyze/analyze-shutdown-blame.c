/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "json-util.h"
#include "analyze.h"
#include "analyze-shutdown-blame.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "log.h"
#include "pager.h"
#include "sort-util.h"
#include "time-util.h"

#define SHUTDOWN_STATS_FILE "/var/lib/systemd/shutdown-stats/last-shutdown.json"

typedef struct UnitShutdownTime {
        char *name;
        usec_t shutdown_time;
} UnitShutdownTime;

static UnitShutdownTime* unit_shutdown_time_free(UnitShutdownTime *t) {
        if (!t)
                return NULL;
        free(t->name);
        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitShutdownTime*, unit_shutdown_time_free);

static int compare_shutdown_time(UnitShutdownTime * const *a, UnitShutdownTime * const *b) {
        assert(a);
        assert(*a);
        assert(b);
        assert(*b);

        return CMP((*b)->shutdown_time, (*a)->shutdown_time);
}

int verb_shutdown_blame(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ UnitShutdownTime **times = NULL;
        _cleanup_free_ char *content = NULL;
        sd_json_variant *units_array, *unit_obj;
        size_t n_units = 0;
        int r;

        /* Read the shutdown stats file */
        r = read_full_file(SHUTDOWN_STATS_FILE, &content, NULL);
        if (r == -ENOENT) {
                log_info("No shutdown statistics found.");
                log_info("Shutdown statistics are saved during system shutdown and analyzed on the next boot.");
                log_info("Please perform a full system shutdown/reboot to generate statistics.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read shutdown statistics: %m");

        /* Parse JSON */
        r = sd_json_parse(content, 0, &v, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse shutdown statistics: %m");

        /* Get units array */
        units_array = sd_json_variant_by_key(v, "units");
        if (!units_array || !sd_json_variant_is_array(units_array)) {
                log_info("No unit shutdown data found in statistics file.");
                return 0;
        }

        /* Parse each unit */
        JSON_VARIANT_ARRAY_FOREACH(unit_obj, units_array) {
                _cleanup_(unit_shutdown_time_freep) UnitShutdownTime *t = NULL;
                sd_json_variant *name_var, *time_var;
                const char *name;
                uint64_t shutdown_time;

                name_var = sd_json_variant_by_key(unit_obj, "unit");
                time_var = sd_json_variant_by_key(unit_obj, "shutdown_time_usec");

                if (!name_var || !sd_json_variant_is_string(name_var))
                        continue;
                if (!time_var || !sd_json_variant_is_unsigned(time_var))
                        continue;

                name = sd_json_variant_string(name_var);
                shutdown_time = sd_json_variant_unsigned(time_var);

                if (shutdown_time == 0)
                        continue;

                t = new0(UnitShutdownTime, 1);
                if (!t)
                        return log_oom();

                t->name = strdup(name);
                if (!t->name)
                        return log_oom();

                t->shutdown_time = shutdown_time;

                if (!GREEDY_REALLOC(times, n_units + 1))
                        return log_oom();

                times[n_units++] = TAKE_PTR(t);
        }

        if (n_units == 0) {
                log_info("No units with shutdown timing data found.");
                return 0;
        }

        /* Sort by shutdown time */
        typesafe_qsort(times, n_units, compare_shutdown_time);

        /* Create output table */
        table = table_new("time", "unit");
        if (!table)
                return log_oom();

        table_set_header(table, false);

        (void) table_set_align_percent(table, table_get_cell(table, 0, 0), 100);
        (void) table_set_ellipsize_percent(table, table_get_cell(table, 0, 1), 100);

        for (size_t i = 0; i < n_units; i++) {
                r = table_add_many(table,
                                 TABLE_TIMESPAN_MSEC, times[i]->shutdown_time,
                                 TABLE_STRING, times[i]->name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        pager_open(arg_pager_flags);

        r = table_print(table, NULL);
        if (r < 0)
                return r;

        /* Free allocated memory */
        for (size_t i = 0; i < n_units; i++)
                unit_shutdown_time_free(times[i]);

        return 0;
}
