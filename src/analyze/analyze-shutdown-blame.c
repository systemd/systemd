/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-shutdown-blame.h"
#include "bus-util.h"
#include "format-table.h"
#include "hashmap.h"
#include "journal-util.h"
#include "log.h"
#include "runtime-scope.h"
#include "sort-util.h"
#include "string-util.h"
#include "time-util.h"

typedef struct ShutdownTime {
        char *name;
        usec_t start_time;
        usec_t stop_time;
        usec_t duration;
} ShutdownTime;

static ShutdownTime* shutdown_time_free(ShutdownTime *t) {
        if (!t)
                return NULL;

        free(t->name);
        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ShutdownTime*, shutdown_time_free);

static int compare_shutdown_times(ShutdownTime * const *a, ShutdownTime * const *b) {
        if ((*a)->duration > (*b)->duration)
                return -1;
        if ((*a)->duration < (*b)->duration)
                return 1;
        return 0;
}

static int acquire_shutdown_times(Hashmap **ret) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(hashmap_freep) Hashmap *shutdown_times = NULL;
        const void *data;
        size_t length;
        int r;

        shutdown_times = hashmap_new(&string_hash_ops);
        if (!shutdown_times)
                return log_oom();

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        /* Look for systemd messages with units */
        r = sd_journal_add_match(j, "SYSLOG_IDENTIFIER=systemd", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add journal match: %m");

        /* Seek to the end and go backwards to find the most recent shutdown */
        r = sd_journal_seek_tail(j);
        if (r < 0)
                return log_error_errno(r, "Failed to seek to journal tail: %m");

        r = sd_journal_previous(j);
        if (r < 0)
                return log_error_errno(r, "Failed to iterate journal: %m");

        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                const char *message = NULL, *unit = NULL;
                usec_t timestamp;
                _cleanup_(shutdown_time_freep) ShutdownTime *st = NULL;
                ShutdownTime *existing;

                r = sd_journal_get_realtime_usec(j, &timestamp);
                if (r < 0)
                        continue;

                r = sd_journal_get_data(j, "MESSAGE", &data, &length);
                if (r < 0)
                        continue;

                message = (const char*) data + STRLEN("MESSAGE=");
                if (length <= STRLEN("MESSAGE="))
                        continue;

                r = sd_journal_get_data(j, "UNIT", &data, &length);
                if (r < 0)
                        continue;

                unit = (const char*) data + STRLEN("UNIT=");
                if (length <= STRLEN("UNIT="))
                        continue;

                /* Skip if this is not a stopping or stopped message */
                if (!startswith(message, "Stopping") && !startswith(message, "Stopped"))
                        continue;

                existing = hashmap_get(shutdown_times, unit);

                if (startswith(message, "Stopping")) {
                        if (existing) {
                                existing->start_time = timestamp;
                                if (existing->stop_time > 0)
                                        existing->duration = existing->stop_time - existing->start_time;
                        } else {
                                st = new0(ShutdownTime, 1);
                                if (!st)
                                        return log_oom();

                                st->name = strndup(unit, strcspn(unit, "\n"));
                                if (!st->name)
                                        return log_oom();

                                st->start_time = timestamp;
                                st->stop_time = 0;
                                st->duration = 0;

                                r = hashmap_put(shutdown_times, st->name, st);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to store shutdown time: %m");

                                TAKE_PTR(st);
                        }
                } else if (startswith(message, "Stopped")) {
                        if (existing) {
                                existing->stop_time = timestamp;
                                if (existing->start_time > 0)
                                        existing->duration = existing->stop_time - existing->start_time;
                        } else {
                                st = new0(ShutdownTime, 1);
                                if (!st)
                                        return log_oom();

                                st->name = strndup(unit, strcspn(unit, "\n"));
                                if (!st->name)
                                        return log_oom();

                                st->start_time = 0;
                                st->stop_time = timestamp;
                                st->duration = 0;

                                r = hashmap_put(shutdown_times, st->name, st);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to store shutdown time: %m");

                                TAKE_PTR(st);
                        }
                }
        }

        *ret = TAKE_PTR(shutdown_times);
        return 0;
}

int verb_shutdown_blame(int argc, char *argv[], void *userdata) {
        _cleanup_(hashmap_freep) Hashmap *shutdown_times = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ ShutdownTime **sorted = NULL;
        size_t n_entries = 0;
        TableCell *cell;
        int r;

        r = acquire_shutdown_times(&shutdown_times);
        if (r < 0)
                return r;

        n_entries = hashmap_size(shutdown_times);
        if (n_entries == 0) {
                log_info("No shutdown timing data found in journal.");
                return 0;
        }

        sorted = new(ShutdownTime*, n_entries);
        if (!sorted)
                return log_oom();

        ShutdownTime *t;
        size_t i = 0;
        HASHMAP_FOREACH(t, shutdown_times) {
                if (t->duration > 0)
                        sorted[i++] = t;
        }
        n_entries = i;

        typesafe_qsort(sorted, n_entries, compare_shutdown_times);

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

        for (size_t j = 0; j < n_entries; j++) {
                r = table_add_many(table,
                                   TABLE_TIMESPAN_MSEC, sorted[j]->duration,
                                   TABLE_STRING, sorted[j]->name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        pager_open(arg_pager_flags);

        r = table_print(table, NULL);
        if (r < 0)
                return r;

        return 0;
}