/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "locale-util.h"
#include "systemctl-list-jobs.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

static int output_waiting_jobs(sd_bus *bus, Table *table, uint32_t id, const char *method, const char *prefix) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *name, *type;
        uint32_t other_id;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_systemd_mgr, method, &error, &reply, "u", id);
        if (r < 0)
                return log_debug_errno(r, "Failed to get waiting jobs for job %" PRIu32, id);

        r = sd_bus_message_enter_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(usssoo)", &other_id, &name, &type, NULL, NULL, NULL)) > 0) {
                _cleanup_free_ char *row = NULL;
                int rc;

                if (asprintf(&row, "%s %u (%s/%s)", prefix, other_id, name, type) < 0)
                        return log_oom();

                rc = table_add_many(table,
                                    TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                                    TABLE_STRING, row,
                                    TABLE_EMPTY,
                                    TABLE_EMPTY);
                if (rc < 0)
                        return table_log_add_error(r);
        }

        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

struct job_info {
        uint32_t id;
        const char *name, *type, *state;
};

static int output_jobs_list(sd_bus *bus, const struct job_info* jobs, unsigned n, bool skipped) {
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *on, *off;
        int r;

        assert(n == 0 || jobs);

        if (n == 0) {
                if (arg_legend != 0) {
                        on = ansi_highlight_green();
                        off = ansi_normal();

                        printf("%sNo jobs %s.%s\n", on, skipped ? "listed" : "running", off);
                }
                return 0;
        }

        pager_open(arg_pager_flags);

        table = table_new("job", "unit", "type", "state");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (const struct job_info *j = jobs; j < jobs + n; j++) {
                if (streq(j->state, "running"))
                        on = ansi_highlight();
                else
                        on =  "";

                r = table_add_many(table,
                                   TABLE_UINT, j->id,
                                   TABLE_STRING, j->name,
                                   TABLE_SET_COLOR, on,
                                   TABLE_STRING, j->type,
                                   TABLE_STRING, j->state,
                                   TABLE_SET_COLOR, on);
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_jobs_after)
                        output_waiting_jobs(bus, table, j->id, "GetJobAfter", "\tblocking job");
                if (arg_jobs_before)
                        output_waiting_jobs(bus, table, j->id, "GetJobBefore", "\twaiting for job");
        }

        r = table_print(table, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to print the table: %m");

        if (arg_legend != 0) {
                on = ansi_highlight();
                off = ansi_normal();

                printf("\n%s%u jobs listed%s.\n", on, n, off);
        }

        return 0;
}

static bool output_show_job(struct job_info *job, char **patterns) {
        return strv_fnmatch_or_empty(patterns, job->name, FNM_NOESCAPE);
}

int verb_list_jobs(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ struct job_info *jobs = NULL;
        const char *name, *type, *state;
        bool skipped = false;
        unsigned c = 0;
        sd_bus *bus;
        uint32_t id;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "ListJobs", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list jobs: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(usssoo)", &id, &name, &type, &state, NULL, NULL)) > 0) {
                struct job_info job = { id, name, type, state };

                if (!output_show_job(&job, strv_skip(argv, 1))) {
                        skipped = true;
                        continue;
                }

                if (!GREEDY_REALLOC(jobs, c + 1))
                        return log_oom();

                jobs[c++] = job;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        pager_open(arg_pager_flags);

        return output_jobs_list(bus, jobs, c, skipped);
}
