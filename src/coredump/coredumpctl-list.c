/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"
#include "sd-json.h"

#include "coredumpctl.h"
#include "coredumpctl-info.h"
#include "coredumpctl-journal.h"
#include "coredumpctl-list.h"
#include "format-table.h"
#include "string-util.h"
#include "strv.h"

int verb_dump_list(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t n_found = 0;
        bool verb_is_info;
        int r;

        verb_is_info = argc >= 1 && streq(argv[0], "info");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        /* The coredumps are likely compressed, and for just listing them we don't need to decompress them,
         * so let's pick a fairly low data threshold here */
        (void) sd_journal_set_data_threshold(j, 4096);

        if (!verb_is_info && !arg_field) {
                t = table_new("id", "time", "pid", "uid", "gid", "sig", "corefile", "exe", "size");
                if (!t)
                        return log_oom();

                (void) table_set_ellipsize_percent(t, TABLE_HEADER_CELL(1), 100);

                (void) table_set_align_percent(t, TABLE_HEADER_CELL(1), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(2), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(3), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(4), 100);
                (void) table_set_align_percent(t, TABLE_HEADER_CELL(8), 100);

                table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
        } else if (!sd_json_format_enabled(arg_json_format_flags))
                pager_open(arg_pager_flags);

        /* "info" without pattern implies "-1" */
        if ((arg_rows_max == 1 && arg_reverse) || (verb_is_info && argc == 1)) {
                r = focus(j);
                if (r < 0)
                        return r;

                r = print_entry(stdout, j, /* need_space= */ false, t);
                if (r < 0)
                        return r;
        } else {
                if (arg_since != USEC_INFINITY && !arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_since);
                else if (arg_until != USEC_INFINITY && arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_until);
                else if (arg_reverse)
                        r = sd_journal_seek_tail(j);
                else
                        r = sd_journal_seek_head(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to date: %m");

                for (;;) {
                        if (!arg_reverse)
                                r = sd_journal_next(j);
                        else
                                r = sd_journal_previous(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate through journal: %m");
                        if (r == 0)
                                break;

                        if (arg_until != USEC_INFINITY && !arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec > arg_until)
                                        break;
                        }

                        if (arg_since != USEC_INFINITY && arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec < arg_since)
                                        break;
                        }

                        r = print_entry(stdout, j, /* need_space= */ n_found > 0, t);
                        if (r < 0)
                                return r;

                        n_found++;

                        if (arg_rows_max != SIZE_MAX && n_found >= arg_rows_max)
                                break;
                }

                if (!arg_field && n_found <= 0) {
                        if (!arg_quiet)
                                log_notice("No coredumps found.");
                        return -ESRCH;
                }
        }

        if (t) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        return 0;
}
