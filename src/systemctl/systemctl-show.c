/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "af-list.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-print-properties.h"
#include "bus-unit-procs.h"
#include "cgroup-show.h"
#include "cpu-set-util.h"
#include "errno-util.h"
#include "exec-util.h"
#include "exit-status.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "ip-protocol-list.h"
#include "journal-file.h"
#include "list.h"
#include "locale-util.h"
#include "memory-util.h"
#include "numa-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "sort-util.h"
#include "special.h"
#include "string-table.h"
#include "systemctl-list-machines.h"
#include "systemctl-list-units.h"
#include "systemctl-show.h"
#include "systemctl-sysv-compat.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "utf8.h"

static OutputFlags get_output_flags(void) {
        return
                FLAGS_SET(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY) * OUTPUT_SHOW_ALL |
                (arg_full || !on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                colors_enabled() * OUTPUT_COLOR |
                !arg_quiet * OUTPUT_WARN_CUTOFF;
}

typedef struct ExecStatusInfo {
        char *name;

        char *path;
        char **argv;

        bool ignore;

        usec_t start_timestamp;
        usec_t exit_timestamp;
        pid_t pid;
        int code;
        int status;

        ExecCommandFlags flags;

        LIST_FIELDS(struct ExecStatusInfo, exec_status_info_list);
} ExecStatusInfo;

static void exec_status_info_free(ExecStatusInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->argv);
        free(i);
}

static int exec_status_info_deserialize(sd_bus_message *m, ExecStatusInfo *i, bool is_ex_prop) {
        _cleanup_strv_free_ char **ex_opts = NULL;
        uint64_t start_timestamp, exit_timestamp, start_timestamp_monotonic, exit_timestamp_monotonic;
        const char *path;
        uint32_t pid;
        int32_t code, status;
        int ignore, r;

        assert(m);
        assert(i);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, is_ex_prop ? "sasasttttuii" : "sasbttttuii");
        if (r < 0)
                return bus_log_parse_error(r);
        if (r == 0)
                return 0;

        r = sd_bus_message_read(m, "s", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        i->path = strdup(path);
        if (!i->path)
                return log_oom();

        r = sd_bus_message_read_strv(m, &i->argv);
        if (r < 0)
                return bus_log_parse_error(r);

        r = is_ex_prop ? sd_bus_message_read_strv(m, &ex_opts) : sd_bus_message_read(m, "b", &ignore);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(m,
                                "ttttuii",
                                &start_timestamp, &start_timestamp_monotonic,
                                &exit_timestamp, &exit_timestamp_monotonic,
                                &pid,
                                &code, &status);
        if (r < 0)
                return bus_log_parse_error(r);

        if (is_ex_prop) {
                r = exec_command_flags_from_strv(ex_opts, &i->flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert strv to ExecCommandFlags: %m");

                i->ignore = FLAGS_SET(i->flags, EXEC_COMMAND_IGNORE_FAILURE);
        } else
                i->ignore = ignore;

        i->start_timestamp = (usec_t) start_timestamp;
        i->exit_timestamp = (usec_t) exit_timestamp;
        i->pid = (pid_t) pid;
        i->code = code;
        i->status = status;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error(r);

        return 1;
}

typedef struct UnitCondition {
        char *name;
        char *param;
        bool trigger;
        bool negate;
        int tristate;

        LIST_FIELDS(struct UnitCondition, conditions);
} UnitCondition;

static UnitCondition* unit_condition_free(UnitCondition *c) {
        if (!c)
                return NULL;

        free(c->name);
        free(c->param);
        return mfree(c);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(UnitCondition*, unit_condition_free);

typedef struct UnitStatusInfo {
        const char *id;
        const char *load_state;
        const char *active_state;
        const char *freezer_state;
        const char *sub_state;
        const char *unit_file_state;
        const char *unit_file_preset;

        const char *description;
        const char *following;

        char **documentation;

        const char *fragment_path;
        const char *source_path;
        const char *control_group;

        char **dropin_paths;

        char **triggered_by;
        char **triggers;

        const char *load_error;
        const char *result;

        usec_t inactive_exit_timestamp;
        usec_t inactive_exit_timestamp_monotonic;
        usec_t active_enter_timestamp;
        usec_t active_exit_timestamp;
        usec_t inactive_enter_timestamp;

        uint64_t runtime_max_sec;

        bool need_daemon_reload;
        bool transient;

        /* Service */
        pid_t main_pid;
        pid_t control_pid;
        const char *status_text;
        const char *pid_file;
        bool running:1;
        int status_errno;

        usec_t start_timestamp;
        usec_t exit_timestamp;

        int exit_code, exit_status;

        const char *log_namespace;

        usec_t condition_timestamp;
        bool condition_result;
        LIST_HEAD(UnitCondition, conditions);

        usec_t assert_timestamp;
        bool assert_result;
        bool failed_assert_trigger;
        bool failed_assert_negate;
        const char *failed_assert;
        const char *failed_assert_parameter;
        usec_t next_elapse_real;
        usec_t next_elapse_monotonic;

        /* Socket */
        unsigned n_accepted;
        unsigned n_connections;
        unsigned n_refused;
        bool accept;

        /* Pairs of type, path */
        char **listen;

        /* Device */
        const char *sysfs_path;

        /* Mount, Automount */
        const char *where;

        /* Swap */
        const char *what;

        /* CGroup */
        uint64_t memory_current;
        uint64_t memory_min;
        uint64_t memory_low;
        uint64_t memory_high;
        uint64_t memory_max;
        uint64_t memory_swap_max;
        uint64_t memory_limit;
        uint64_t memory_available;
        uint64_t cpu_usage_nsec;
        uint64_t tasks_current;
        uint64_t tasks_max;
        uint64_t ip_ingress_bytes;
        uint64_t ip_egress_bytes;
        uint64_t io_read_bytes;
        uint64_t io_write_bytes;

        uint64_t default_memory_min;
        uint64_t default_memory_low;

        LIST_HEAD(ExecStatusInfo, exec_status_info_list);
} UnitStatusInfo;

static void unit_status_info_free(UnitStatusInfo *info) {
        ExecStatusInfo *p;
        UnitCondition *c;

        strv_free(info->documentation);
        strv_free(info->dropin_paths);
        strv_free(info->triggered_by);
        strv_free(info->triggers);
        strv_free(info->listen);

        while ((c = info->conditions)) {
                LIST_REMOVE(conditions, info->conditions, c);
                unit_condition_free(c);
        }

        while ((p = info->exec_status_info_list)) {
                LIST_REMOVE(exec_status_info_list, info->exec_status_info_list, p);
                exec_status_info_free(p);
        }
}

static void format_active_state(const char *active_state, const char **active_on, const char **active_off) {
        if (streq_ptr(active_state, "failed")) {
                *active_on = ansi_highlight_red();
                *active_off = ansi_normal();
        } else if (STRPTR_IN_SET(active_state, "active", "reloading")) {
                *active_on = ansi_highlight_green();
                *active_off = ansi_normal();
        } else
                *active_on = *active_off = "";
}

static void format_enable_state(const char *enable_state, const char **enable_on, const char **enable_off) {
        assert(enable_on);
        assert(enable_off);

        if (streq_ptr(enable_state, "disabled")) {
                *enable_on = ansi_highlight_yellow();
                *enable_off = ansi_normal();
        } else if (streq_ptr(enable_state, "enabled")) {
                *enable_on = ansi_highlight_green();
                *enable_off = ansi_normal();
        } else
                *enable_on = *enable_off = "";
}

static void print_status_info(
                sd_bus *bus,
                UnitStatusInfo *i,
                bool *ellipsized) {

        const char *active_on, *active_off, *on, *off, *ss, *fs;
        const char *enable_on, *enable_off, *preset_on, *preset_off;
        _cleanup_free_ char *formatted_path = NULL;
        usec_t timestamp;
        const char *path;
        int r;

        assert(i);

        /* This shows pretty information about a unit. See print_property() for a low-level property
         * printer */

        format_active_state(i->active_state, &active_on, &active_off);
        format_enable_state(i->unit_file_state, &enable_on, &enable_off);
        format_enable_state(i->unit_file_preset, &preset_on, &preset_off);

        const SpecialGlyph glyph = unit_active_state_to_glyph(unit_active_state_from_string(i->active_state));

        printf("%s%s%s %s", active_on, special_glyph(glyph), active_off, strna(i->id));

        if (i->description && !streq_ptr(i->id, i->description))
                printf(" - %s", i->description);

        printf("\n");

        if (i->following)
                printf("    Follows: unit currently follows state of %s\n", i->following);

        if (STRPTR_IN_SET(i->load_state, "error", "not-found", "bad-setting")) {
                on = ansi_highlight_red();
                off = ansi_normal();
        } else
                on = off = "";

        path = i->source_path ?: i->fragment_path;
        if (path && terminal_urlify_path(path, NULL, &formatted_path) >= 0)
                path = formatted_path;

        if (!isempty(i->load_error))
                printf("     Loaded: %s%s%s (Reason: %s)\n",
                       on, strna(i->load_state), off, i->load_error);
        else if (path && !isempty(i->unit_file_state)) {
                bool show_preset = !isempty(i->unit_file_preset) &&
                        show_preset_for_state(unit_file_state_from_string(i->unit_file_state));

                printf("     Loaded: %s%s%s (%s; %s%s%s%s%s%s%s)\n",
                       on, strna(i->load_state), off,
                       path,
                       enable_on, i->unit_file_state, enable_off,
                       show_preset ? "; preset: " : "",
                       preset_on, show_preset ? i->unit_file_preset : "", preset_off);

        } else if (path)
                printf("     Loaded: %s%s%s (%s)\n",
                       on, strna(i->load_state), off, path);
        else
                printf("     Loaded: %s%s%s\n",
                       on, strna(i->load_state), off);

        if (i->transient)
                printf("  Transient: yes\n");

        if (!strv_isempty(i->dropin_paths)) {
                _cleanup_free_ char *dir = NULL;
                bool last = false;

                STRV_FOREACH(dropin, i->dropin_paths) {
                        _cleanup_free_ char *dropin_formatted = NULL;
                        const char *df;

                        if (!dir || last) {
                                printf(dir ? "             " :
                                             "    Drop-In: ");

                                dir = mfree(dir);

                                r = path_extract_directory(*dropin, &dir);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to extract directory of '%s': %m", *dropin);
                                        break;
                                }

                                printf("%s\n"
                                       "             %s", dir,
                                       special_glyph(SPECIAL_GLYPH_TREE_RIGHT));
                        }

                        last = ! (*(dropin + 1) && startswith(*(dropin + 1), dir));

                        if (terminal_urlify_path(*dropin, basename(*dropin), &dropin_formatted) >= 0)
                                df = dropin_formatted;
                        else
                                df = *dropin;

                        printf("%s%s", df, last ? "\n" : ", ");
                }
        }

        ss = streq_ptr(i->active_state, i->sub_state) ? NULL : i->sub_state;
        if (ss)
                printf("     Active: %s%s (%s)%s",
                       active_on, strna(i->active_state), ss, active_off);
        else
                printf("     Active: %s%s%s",
                       active_on, strna(i->active_state), active_off);

        fs = !isempty(i->freezer_state) && !streq(i->freezer_state, "running") ? i->freezer_state : NULL;
        if (fs)
                printf(" %s(%s)%s", ansi_highlight_yellow(), fs, ansi_normal());

        if (!isempty(i->result) && !streq(i->result, "success"))
                printf(" (Result: %s)", i->result);

        timestamp = STRPTR_IN_SET(i->active_state, "active", "reloading") ? i->active_enter_timestamp :
                    STRPTR_IN_SET(i->active_state, "inactive", "failed")  ? i->inactive_enter_timestamp :
                    STRPTR_IN_SET(i->active_state, "activating")          ? i->inactive_exit_timestamp :
                                                                            i->active_exit_timestamp;

        if (timestamp_is_set(timestamp)) {
                printf(" since %s; %s\n",
                       FORMAT_TIMESTAMP_STYLE(timestamp, arg_timestamp_style),
                       FORMAT_TIMESTAMP_RELATIVE(timestamp));
                if (streq_ptr(i->active_state, "active") && i->runtime_max_sec < USEC_INFINITY) {
                        usec_t until_timestamp;

                        until_timestamp = usec_add(timestamp, i->runtime_max_sec);
                        printf("      Until: %s; %s\n",
                               FORMAT_TIMESTAMP_STYLE(until_timestamp, arg_timestamp_style),
                               FORMAT_TIMESTAMP_RELATIVE(until_timestamp));
                }

                if (!endswith(i->id, ".target") &&
                        STRPTR_IN_SET(i->active_state, "inactive", "failed") &&
                        timestamp_is_set(i->active_enter_timestamp) &&
                        timestamp_is_set(i->active_exit_timestamp) &&
                        i->active_exit_timestamp >= i->active_enter_timestamp) {

                        usec_t duration;

                        duration = i->active_exit_timestamp - i->active_enter_timestamp;
                        printf("   Duration: %s\n", FORMAT_TIMESPAN(duration, MSEC_PER_SEC));
                }
        } else
                printf("\n");

        STRV_FOREACH(t, i->triggered_by) {
                UnitActiveState state = _UNIT_ACTIVE_STATE_INVALID;

                (void) get_state_one_unit(bus, *t, &state);
                format_active_state(unit_active_state_to_string(state), &on, &off);

                printf("%s %s%s%s %s\n",
                       t == i->triggered_by ? "TriggeredBy:" : "            ",
                       on, special_glyph(unit_active_state_to_glyph(state)), off,
                       *t);
        }

        if (endswith(i->id, ".timer")) {
                dual_timestamp nw, next = {i->next_elapse_real, i->next_elapse_monotonic};
                usec_t next_elapse;

                dual_timestamp_get(&nw);
                next_elapse = calc_next_elapse(&nw, &next);

                if (timestamp_is_set(next_elapse))
                        printf("    Trigger: %s; %s\n",
                               FORMAT_TIMESTAMP_STYLE(next_elapse, arg_timestamp_style),
                               FORMAT_TIMESTAMP_RELATIVE(next_elapse));
                else
                        printf("    Trigger: n/a\n");
        }

        STRV_FOREACH(t, i->triggers) {
                UnitActiveState state = _UNIT_ACTIVE_STATE_INVALID;

                (void) get_state_one_unit(bus, *t, &state);
                format_active_state(unit_active_state_to_string(state), &on, &off);

                printf("%s %s%s%s %s\n",
                       t == i->triggers ? "   Triggers:" : "            ",
                       on, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE), off,
                       *t);
        }

        if (!i->condition_result && i->condition_timestamp > 0) {
                int n = 0;

                printf("  Condition: start %scondition failed%s at %s; %s\n",
                       ansi_highlight_yellow(), ansi_normal(),
                       FORMAT_TIMESTAMP_STYLE(i->condition_timestamp, arg_timestamp_style),
                       FORMAT_TIMESTAMP_RELATIVE(i->condition_timestamp));

                LIST_FOREACH(conditions, c, i->conditions)
                        if (c->tristate < 0)
                                n++;

                LIST_FOREACH(conditions, c, i->conditions)
                        if (c->tristate < 0)
                                printf("             %s %s=%s%s%s was not met\n",
                                       --n ? special_glyph(SPECIAL_GLYPH_TREE_BRANCH) : special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                                       c->name,
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->param);
        }

        if (!i->assert_result && i->assert_timestamp > 0) {
                printf("     Assert: start %sassertion failed%s at %s; %s\n",
                       ansi_highlight_red(), ansi_normal(),
                       FORMAT_TIMESTAMP_STYLE(i->assert_timestamp, arg_timestamp_style),
                       FORMAT_TIMESTAMP_RELATIVE(i->assert_timestamp));
                if (i->failed_assert_trigger)
                        printf("             none of the trigger assertions were met\n");
                else if (i->failed_assert)
                        printf("             %s=%s%s was not met\n",
                               i->failed_assert,
                               i->failed_assert_negate ? "!" : "",
                               i->failed_assert_parameter);
        }

        if (i->sysfs_path)
                printf("     Device: %s\n", i->sysfs_path);
        if (i->where)
                printf("      Where: %s\n", i->where);
        if (i->what)
                printf("       What: %s\n", i->what);

        STRV_FOREACH(t, i->documentation) {
                _cleanup_free_ char *formatted = NULL;
                const char *q;

                if (terminal_urlify(*t, NULL, &formatted) >= 0)
                        q = formatted;
                else
                        q = *t;

                printf("   %*s %s\n", 9, t == i->documentation ? "Docs:" : "", q);
        }

        STRV_FOREACH_PAIR(t, t2, i->listen)
                printf("   %*s %s (%s)\n", 9, t == i->listen ? "Listen:" : "", *t2, *t);

        if (i->accept) {
                printf("   Accepted: %u; Connected: %u;", i->n_accepted, i->n_connections);
                if (i->n_refused)
                        printf("   Refused: %u", i->n_refused);
                printf("\n");
        }

        LIST_FOREACH(exec_status_info_list, p, i->exec_status_info_list) {
                _cleanup_free_ char *argv = NULL;
                bool good;

                /* Only show exited processes here */
                if (p->code == 0)
                        continue;

                /* Don't print ExecXYZEx= properties here since it will appear as a
                 * duplicate of the non-Ex= variant. */
                if (endswith(p->name, "Ex"))
                        continue;

                argv = strv_join(p->argv, " ");
                printf("    Process: "PID_FMT" %s=%s ", p->pid, p->name, strna(argv));

                good = is_clean_exit(p->code, p->status, EXIT_CLEAN_DAEMON, NULL);
                if (!good) {
                        on = p->ignore ? ansi_highlight_yellow() : ansi_highlight_red();
                        off = ansi_normal();
                } else
                        on = off = "";

                printf("%s(code=%s, ", on, sigchld_code_to_string(p->code));

                if (p->code == CLD_EXITED) {
                        const char *c;

                        printf("status=%i", p->status);

                        c = exit_status_to_string(p->status, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);
                        if (c)
                                printf("/%s", c);

                } else
                        printf("signal=%s", signal_to_string(p->status));

                printf(")%s\n", off);

                if (i->main_pid == p->pid &&
                    i->start_timestamp == p->start_timestamp &&
                    i->exit_timestamp == p->start_timestamp)
                        /* Let's not show this twice */
                        i->main_pid = 0;

                if (p->pid == i->control_pid)
                        i->control_pid = 0;
        }

        if (i->main_pid > 0 || i->control_pid > 0) {
                if (i->main_pid > 0) {
                        printf("   Main PID: "PID_FMT, i->main_pid);

                        if (i->running) {

                                if (arg_transport == BUS_TRANSPORT_LOCAL) {
                                        _cleanup_free_ char *comm = NULL;

                                        (void) get_process_comm(i->main_pid, &comm);
                                        if (comm)
                                                printf(" (%s)", comm);
                                }

                        } else if (i->exit_code > 0) {
                                printf(" (code=%s, ", sigchld_code_to_string(i->exit_code));

                                if (i->exit_code == CLD_EXITED) {
                                        const char *c;

                                        printf("status=%i", i->exit_status);

                                        c = exit_status_to_string(i->exit_status,
                                                                  EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);
                                        if (c)
                                                printf("/%s", c);

                                } else
                                        printf("signal=%s", signal_to_string(i->exit_status));
                                printf(")");
                        }
                }

                if (i->control_pid > 0) {
                        _cleanup_free_ char *c = NULL;

                        if (i->main_pid > 0)
                                fputs("; Control PID: ", stdout);
                        else
                                fputs("Cntrl PID: ", stdout); /* if first in column, abbreviated so it fits alignment */

                        printf(PID_FMT, i->control_pid);

                        if (arg_transport == BUS_TRANSPORT_LOCAL) {
                                (void) get_process_comm(i->control_pid, &c);
                                if (c)
                                        printf(" (%s)", c);
                        }
                }

                printf("\n");
        }

        if (i->status_text)
                printf("     Status: \"%s\"\n", i->status_text);
        if (i->status_errno > 0) {
                errno = i->status_errno;
                printf("      Error: %i (%m)\n", i->status_errno);
        }

        if (i->ip_ingress_bytes != UINT64_MAX && i->ip_egress_bytes != UINT64_MAX)
                printf("         IP: %s in, %s out\n",
                       FORMAT_BYTES(i->ip_ingress_bytes),
                       FORMAT_BYTES(i->ip_egress_bytes));

        if (i->io_read_bytes != UINT64_MAX && i->io_write_bytes != UINT64_MAX)
                printf("         IO: %s read, %s written\n",
                        FORMAT_BYTES(i->io_read_bytes),
                        FORMAT_BYTES(i->io_write_bytes));

        if (i->tasks_current != UINT64_MAX) {
                printf("      Tasks: %" PRIu64, i->tasks_current);

                if (i->tasks_max != UINT64_MAX)
                        printf(" (limit: %" PRIu64 ")\n", i->tasks_max);
                else
                        printf("\n");
        }

        if (i->memory_current != UINT64_MAX) {
                printf("     Memory: %s", FORMAT_BYTES(i->memory_current));

                if (i->memory_min > 0 || i->memory_low > 0 ||
                    i->memory_high != CGROUP_LIMIT_MAX || i->memory_max != CGROUP_LIMIT_MAX ||
                    i->memory_swap_max != CGROUP_LIMIT_MAX ||
                    i->memory_available != CGROUP_LIMIT_MAX ||
                    i->memory_limit != CGROUP_LIMIT_MAX) {
                        const char *prefix = "";

                        printf(" (");
                        if (i->memory_min > 0) {
                                printf("%smin: %s", prefix, FORMAT_BYTES_CGROUP_PROTECTION(i->memory_min));
                                prefix = " ";
                        }
                        if (i->memory_low > 0) {
                                printf("%slow: %s", prefix, FORMAT_BYTES_CGROUP_PROTECTION(i->memory_low));
                                prefix = " ";
                        }
                        if (i->memory_high != CGROUP_LIMIT_MAX) {
                                printf("%shigh: %s", prefix, FORMAT_BYTES(i->memory_high));
                                prefix = " ";
                        }
                        if (i->memory_max != CGROUP_LIMIT_MAX) {
                                printf("%smax: %s", prefix, FORMAT_BYTES(i->memory_max));
                                prefix = " ";
                        }
                        if (i->memory_swap_max != CGROUP_LIMIT_MAX) {
                                printf("%sswap max: %s", prefix, FORMAT_BYTES(i->memory_swap_max));
                                prefix = " ";
                        }
                        if (i->memory_limit != CGROUP_LIMIT_MAX) {
                                printf("%slimit: %s", prefix, FORMAT_BYTES(i->memory_limit));
                                prefix = " ";
                        }
                        if (i->memory_available != CGROUP_LIMIT_MAX) {
                                printf("%savailable: %s", prefix, FORMAT_BYTES(i->memory_available));
                                prefix = " ";
                        }
                        printf(")");
                }
                printf("\n");
        }

        if (i->cpu_usage_nsec != UINT64_MAX)
                printf("        CPU: %s\n", FORMAT_TIMESPAN(i->cpu_usage_nsec / NSEC_PER_USEC, USEC_PER_MSEC));

        if (i->control_group) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                static const char prefix[] = "             ";
                unsigned c;

                printf("     CGroup: %s\n", i->control_group);

                c = LESS_BY(columns(), strlen(prefix));

                r = unit_show_processes(bus, i->id, i->control_group, prefix, c, get_output_flags(), &error);
                if (r == -EBADR && arg_transport == BUS_TRANSPORT_LOCAL) {
                        unsigned k = 0;
                        pid_t extra[2];

                        /* Fallback for older systemd versions where the GetUnitProcesses() call is not yet available */

                        if (i->main_pid > 0)
                                extra[k++] = i->main_pid;

                        if (i->control_pid > 0)
                                extra[k++] = i->control_pid;

                        show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, i->control_group, prefix, c, extra, k, get_output_flags());
                } else if (r < 0)
                        log_warning_errno(r, "Failed to dump process list for '%s', ignoring: %s",
                                          i->id, bus_error_message(&error, r));
        }

        if (i->id && arg_transport == BUS_TRANSPORT_LOCAL)
                show_journal_by_unit(
                                stdout,
                                i->id,
                                i->log_namespace,
                                arg_output,
                                0,
                                i->inactive_exit_timestamp_monotonic,
                                arg_lines,
                                getuid(),
                                get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                                SD_JOURNAL_LOCAL_ONLY,
                                arg_scope == LOOKUP_SCOPE_SYSTEM,
                                ellipsized);

        if (i->need_daemon_reload)
                warn_unit_file_changed(i->id);
}

static void show_unit_help(UnitStatusInfo *i) {
        assert(i);

        if (!i->documentation) {
                log_info("Documentation for %s not known.", i->id);
                return;
        }

        STRV_FOREACH(p, i->documentation)
                if (startswith(*p, "man:"))
                        show_man_page(*p + 4, false);
                else
                        log_info("Can't show: %s", *p);
}

static int map_main_pid(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        UnitStatusInfo *i = userdata;
        uint32_t u;
        int r;

        r = sd_bus_message_read(m, "u", &u);
        if (r < 0)
                return r;

        i->main_pid = (pid_t) u;
        i->running = u > 0;

        return 0;
}

static int map_load_error(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        const char *message, **p = userdata;
        int r;

        r = sd_bus_message_read(m, "(ss)", NULL, &message);
        if (r < 0)
                return r;

        if (!isempty(message))
                *p = message;

        return 0;
}

static int map_listen(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        const char *type, *path;
        char ***p = userdata;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(m, "(ss)", &type, &path)) > 0) {

                r = strv_extend(p, type);
                if (r < 0)
                        return r;

                r = strv_extend(p, path);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_conditions(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        UnitStatusInfo *i = userdata;
        const char *cond, *param;
        int trigger, negate;
        int32_t state;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sbbsi)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(m, "(sbbsi)", &cond, &trigger, &negate, &param, &state)) > 0) {
                _cleanup_(unit_condition_freep) UnitCondition *c = NULL;

                c = new(UnitCondition, 1);
                if (!c)
                        return -ENOMEM;

                *c = (UnitCondition) {
                        .name = strdup(cond),
                        .param = strdup(param),
                        .trigger = trigger,
                        .negate = negate,
                        .tristate = state,
                };

                if (!c->name || !c->param)
                        return -ENOMEM;

                LIST_PREPEND(conditions, i->conditions, TAKE_PTR(c));
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_asserts(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        UnitStatusInfo *i = userdata;
        const char *cond, *param;
        int trigger, negate;
        int32_t state;
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sbbsi)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(m, "(sbbsi)", &cond, &trigger, &negate, &param, &state)) > 0) {
                if (state < 0 && (!trigger || !i->failed_assert)) {
                        i->failed_assert = cond;
                        i->failed_assert_trigger = trigger;
                        i->failed_assert_negate = negate;
                        i->failed_assert_parameter = param;
                }
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int map_exec(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        _cleanup_free_ ExecStatusInfo *info = NULL;
        ExecStatusInfo *last;
        UnitStatusInfo *i = userdata;
        bool is_ex_prop = endswith(member, "Ex");
        int r;

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, is_ex_prop ? "(sasasttttuii)" : "(sasbttttuii)");
        if (r < 0)
                return r;

        info = new0(ExecStatusInfo, 1);
        if (!info)
                return -ENOMEM;

        LIST_FIND_TAIL(exec_status_info_list, i->exec_status_info_list, last);

        while ((r = exec_status_info_deserialize(m, info, is_ex_prop)) > 0) {

                info->name = strdup(member);
                if (!info->name)
                        return -ENOMEM;

                LIST_INSERT_AFTER(exec_status_info_list, i->exec_status_info_list, last, info);
                last = info;

                info = new0(ExecStatusInfo, 1);
                if (!info)
                        return -ENOMEM;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int print_property(const char *name, const char *expected_value, sd_bus_message *m, BusPrintPropertyFlags flags) {
        char bus_type;
        const char *contents;
        int r;

        assert(name);
        assert(m);

        /* This is a low-level property printer, see print_status_info() for the nicer output */

        r = sd_bus_message_peek_type(m, &bus_type, &contents);
        if (r < 0)
                return r;

        switch (bus_type) {

        case SD_BUS_TYPE_INT32:
                if (endswith(name, "ActionExitStatus")) {
                        int32_t i;

                        r = sd_bus_message_read_basic(m, bus_type, &i);
                        if (r < 0)
                                return r;

                        if (i >= 0 && i <= 255)
                                bus_print_property_valuef(name, expected_value, flags, "%"PRIi32, i);
                        else if (FLAGS_SET(flags, BUS_PRINT_PROPERTY_SHOW_EMPTY))
                                bus_print_property_value(name, expected_value, flags, "[not set]");

                        return 1;
                } else if (streq(name, "NUMAPolicy")) {
                        int32_t i;

                        r = sd_bus_message_read_basic(m, bus_type, &i);
                        if (r < 0)
                                return r;

                        bus_print_property_valuef(name, expected_value, flags, "%s", strna(mpol_to_string(i)));

                        return 1;
                }
                break;

        case SD_BUS_TYPE_UINT64:
                if (endswith(name, "Timestamp")) {
                        uint64_t timestamp;

                        r = sd_bus_message_read_basic(m, bus_type, &timestamp);
                        if (r < 0)
                                return r;

                        bus_print_property_value(name, expected_value, flags, FORMAT_TIMESTAMP_STYLE(timestamp, arg_timestamp_style));

                        return 1;
                }
                break;

        case SD_BUS_TYPE_STRUCT:

                if (contents[0] == SD_BUS_TYPE_UINT32 && streq(name, "Job")) {
                        uint32_t u;

                        r = sd_bus_message_read(m, "(uo)", &u, NULL);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (u > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%"PRIu32, u);
                        else
                                bus_print_property_value(name, expected_value, flags, NULL);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRING && streq(name, "Unit")) {
                        const char *s;

                        r = sd_bus_message_read(m, "(so)", &s, NULL);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, s);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRING && streq(name, "LoadError")) {
                        const char *a = NULL, *b = NULL;

                        r = sd_bus_message_read(m, "(ss)", &a, &b);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (!isempty(a) || !isempty(b))
                                bus_print_property_valuef(name, expected_value, flags, "%s \"%s\"", strempty(a), strempty(b));
                        else
                                bus_print_property_value(name, expected_value, flags, NULL);

                        return 1;

                } else if (STR_IN_SET(name, "SystemCallFilter", "SystemCallLog", "RestrictAddressFamilies", "RestrictNetworkInterfaces", "RestrictFileSystems")) {
                        _cleanup_strv_free_ char **l = NULL;
                        int allow_list;

                        r = sd_bus_message_enter_container(m, 'r', "bas");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_read(m, "b", &allow_list);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_read_strv(m, &l);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (FLAGS_SET(flags, BUS_PRINT_PROPERTY_SHOW_EMPTY) || allow_list || !strv_isempty(l)) {
                                bool first = true;

                                if (!FLAGS_SET(flags, BUS_PRINT_PROPERTY_ONLY_VALUE)) {
                                        fputs(name, stdout);
                                        fputc('=', stdout);
                                }

                                if (!allow_list)
                                        fputc('~', stdout);

                                STRV_FOREACH(i, l) {
                                        if (first)
                                                first = false;
                                        else
                                                fputc(' ', stdout);

                                        fputs(*i, stdout);
                                }
                                fputc('\n', stdout);
                        }

                        return 1;

                } else if (STR_IN_SET(name, "SELinuxContext", "AppArmorProfile", "SmackProcessLabel")) {
                        int ignore;
                        const char *s;

                        r = sd_bus_message_read(m, "(bs)", &ignore, &s);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (!isempty(s))
                                bus_print_property_valuef(name, expected_value, flags, "%s%s", ignore ? "-" : "", s);
                        else
                                bus_print_property_value(name, expected_value, flags, NULL);

                        return 1;

                } else if (endswith(name, "ExitStatus") && streq(contents, "aiai")) {
                        const int32_t *status, *signal;
                        size_t n_status, n_signal;

                        r = sd_bus_message_enter_container(m, 'r', "aiai");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_read_array(m, 'i', (const void **) &status, &n_status);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_read_array(m, 'i', (const void **) &signal, &n_signal);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        n_status /= sizeof(int32_t);
                        n_signal /= sizeof(int32_t);

                        if (FLAGS_SET(flags, BUS_PRINT_PROPERTY_SHOW_EMPTY) || n_status > 0 || n_signal > 0) {
                                bool first = true;

                                if (!FLAGS_SET(flags, BUS_PRINT_PROPERTY_ONLY_VALUE)) {
                                        fputs(name, stdout);
                                        fputc('=', stdout);
                                }

                                for (size_t i = 0; i < n_status; i++) {
                                        if (first)
                                                first = false;
                                        else
                                                fputc(' ', stdout);

                                        printf("%"PRIi32, status[i]);
                                }

                                for (size_t i = 0; i < n_signal; i++) {
                                        const char *str;

                                        str = signal_to_string((int) signal[i]);

                                        if (first)
                                                first = false;
                                        else
                                                fputc(' ', stdout);

                                        if (str)
                                                fputs(str, stdout);
                                        else
                                                printf("%"PRIi32, status[i]);
                                }

                                fputc('\n', stdout);
                        }
                        return 1;
                }

                break;

        case SD_BUS_TYPE_ARRAY:

                if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "EnvironmentFiles")) {
                        const char *path;
                        int ignore;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sb)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(sb)", &path, &ignore)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s (ignore_errors=%s)", path, yes_no(ignore));
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "Paths")) {
                        const char *type, *path;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ss)", &type, &path)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s (%s)", path, type);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "Listen")) {
                        const char *type, *path;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ss)", &type, &path)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s (%s)", path, type);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "TimersMonotonic")) {
                        const char *base;
                        uint64_t v, next_elapse;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(stt)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(stt)", &base, &v, &next_elapse)) > 0)
                                bus_print_property_valuef(name, expected_value, flags,
                                                          "{ %s=%s ; next_elapse=%s }",
                                                          base,
                                                          strna(FORMAT_TIMESPAN(v, 0)),
                                                          strna(FORMAT_TIMESPAN(next_elapse, 0)));
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "TimersCalendar")) {
                        const char *base, *spec;
                        uint64_t next_elapse;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sst)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(sst)", &base, &spec, &next_elapse)) > 0)
                                bus_print_property_valuef(name, expected_value, flags,
                                                          "{ %s=%s ; next_elapse=%s }", base, spec,
                                                          FORMAT_TIMESTAMP_STYLE(next_elapse, arg_timestamp_style));
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && startswith(name, "Exec")) {
                        ExecStatusInfo info = {};
                        bool is_ex_prop = endswith(name, "Ex");

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, is_ex_prop ? "(sasasttttuii)" : "(sasbttttuii)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = exec_status_info_deserialize(m, &info, is_ex_prop)) > 0) {
                                _cleanup_strv_free_ char **optv = NULL;
                                _cleanup_free_ char *tt = NULL, *o = NULL;

                                tt = strv_join(info.argv, " ");

                                if (is_ex_prop) {
                                        r = exec_command_flags_to_strv(info.flags, &optv);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to convert ExecCommandFlags to strv: %m");

                                        o = strv_join(optv, " ");

                                        bus_print_property_valuef(name, expected_value, flags,
                                                                  "{ path=%s ; argv[]=%s ; flags=%s ; start_time=[%s] ; stop_time=[%s] ; pid="PID_FMT" ; code=%s ; status=%i%s%s }",
                                                                  strna(info.path),
                                                                  strna(tt),
                                                                  strna(o),
                                                                  strna(FORMAT_TIMESTAMP_STYLE(info.start_timestamp, arg_timestamp_style)),
                                                                  strna(FORMAT_TIMESTAMP_STYLE(info.exit_timestamp, arg_timestamp_style)),
                                                                  info.pid,
                                                                  sigchld_code_to_string(info.code),
                                                                  info.status,
                                                                  info.code == CLD_EXITED ? "" : "/",
                                                                  strempty(info.code == CLD_EXITED ? NULL : signal_to_string(info.status)));
                                } else
                                        bus_print_property_valuef(name, expected_value, flags,
                                                                  "{ path=%s ; argv[]=%s ; ignore_errors=%s ; start_time=[%s] ; stop_time=[%s] ; pid="PID_FMT" ; code=%s ; status=%i%s%s }",
                                                                  strna(info.path),
                                                                  strna(tt),
                                                                  yes_no(info.ignore),
                                                                  strna(FORMAT_TIMESTAMP_STYLE(info.start_timestamp, arg_timestamp_style)),
                                                                  strna(FORMAT_TIMESTAMP_STYLE(info.exit_timestamp, arg_timestamp_style)),
                                                                  info.pid,
                                                                  sigchld_code_to_string(info.code),
                                                                  info.status,
                                                                  info.code == CLD_EXITED ? "" : "/",
                                                                  strempty(info.code == CLD_EXITED ? NULL : signal_to_string(info.status)));

                                free(info.path);
                                strv_free(info.argv);
                                zero(info);
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN && streq(name, "DeviceAllow")) {
                        const char *path, *rwm;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ss)", &path, &rwm)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s %s", strna(path), strna(rwm));
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN &&
                           STR_IN_SET(name, "IODeviceWeight", "BlockIODeviceWeight")) {
                        const char *path;
                        uint64_t weight;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(st)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(st)", &path, &weight)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s %"PRIu64, strna(path), weight);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN &&
                           (cgroup_io_limit_type_from_string(name) >= 0 ||
                            STR_IN_SET(name, "BlockIOReadBandwidth", "BlockIOWriteBandwidth"))) {
                        const char *path;
                        uint64_t bandwidth;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(st)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(st)", &path, &bandwidth)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s %"PRIu64, strna(path), bandwidth);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                }  else if (contents[0] == SD_BUS_TYPE_STRUCT_BEGIN &&
                            streq(name, "IODeviceLatencyTargetUSec")) {
                        const char *path;
                        uint64_t target;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(st)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(st)", &path, &target)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s %s", strna(path),
                                                          FORMAT_TIMESPAN(target, 1));
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;

                } else if (contents[0] == SD_BUS_TYPE_BYTE && STR_IN_SET(name, "StandardInputData", "RootHashSignature")) {
                        _cleanup_free_ char *h = NULL;
                        const void *p;
                        size_t sz;
                        ssize_t n;

                        r = sd_bus_message_read_array(m, 'y', &p, &sz);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        n = base64mem(p, sz, &h);
                        if (n < 0)
                                return log_oom();

                        bus_print_property_value(name, expected_value, flags, h);

                        return 1;

                } else if (STR_IN_SET(name, "IPAddressAllow", "IPAddressDeny")) {
                        _cleanup_free_ char *addresses = NULL;

                        r = sd_bus_message_enter_container(m, 'a', "(iayu)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        for (;;) {
                                uint32_t prefixlen;
                                int32_t family;
                                const void *ap;
                                size_t an;

                                r = sd_bus_message_enter_container(m, 'r', "iayu");
                                if (r < 0)
                                        return bus_log_parse_error(r);
                                if (r == 0)
                                        break;

                                r = sd_bus_message_read(m, "i", &family);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = sd_bus_message_read_array(m, 'y', &ap, &an);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = sd_bus_message_read(m, "u", &prefixlen);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = sd_bus_message_exit_container(m);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                if (!IN_SET(family, AF_INET, AF_INET6))
                                        continue;

                                if (an != FAMILY_ADDRESS_SIZE(family))
                                        continue;

                                if (prefixlen > FAMILY_ADDRESS_SIZE(family) * 8)
                                        continue;

                                if (!strextend_with_separator(&addresses, " ",
                                                              IN_ADDR_PREFIX_TO_STRING(family, ap, prefixlen)))
                                        return log_oom();
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, addresses);

                        return 1;

                } else if (STR_IN_SET(name, "BindPaths", "BindReadOnlyPaths")) {
                        _cleanup_free_ char *paths = NULL;
                        const char *source, *dest;
                        int ignore_enoent;
                        uint64_t rbind;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ssbt)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ssbt)", &source, &dest, &ignore_enoent, &rbind)) > 0) {
                                _cleanup_free_ char *str = NULL;

                                if (isempty(source))
                                        continue;

                                if (asprintf(&str, "%s%s%s%s%s",
                                             ignore_enoent ? "-" : "",
                                             source,
                                             isempty(dest) ? "" : ":",
                                             strempty(dest),
                                             rbind == MS_REC ? ":rbind" : "") < 0)
                                        return log_oom();

                                if (!strextend_with_separator(&paths, " ", str))
                                        return log_oom();
                        }
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, paths);

                        return 1;

                } else if (streq(name, "TemporaryFileSystem")) {
                        _cleanup_free_ char *paths = NULL;
                        const char *target, *option;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ss)", &target, &option)) > 0) {
                                _cleanup_free_ char *str = NULL;

                                if (isempty(target))
                                        continue;

                                if (asprintf(&str, "%s%s%s", target, isempty(option) ? "" : ":", strempty(option)) < 0)
                                        return log_oom();

                                if (!strextend_with_separator(&paths, " ", str))
                                        return log_oom();
                        }
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, paths);

                        return 1;

                } else if (streq(name, "LogExtraFields")) {
                        _cleanup_free_ char *fields = NULL;
                        const void *p;
                        size_t sz;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "ay");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read_array(m, 'y', &p, &sz)) > 0) {
                                _cleanup_free_ char *str = NULL;
                                const char *eq;

                                if (memchr(p, 0, sz))
                                        continue;

                                eq = memchr(p, '=', sz);
                                if (!eq)
                                        continue;

                                if (!journal_field_valid(p, eq - (const char*) p, false))
                                        continue;

                                str = malloc(sz + 1);
                                if (!str)
                                        return log_oom();

                                memcpy(str, p, sz);
                                str[sz] = '\0';

                                if (!utf8_is_valid(str))
                                        continue;

                                if (!strextend_with_separator(&fields, " ", str))
                                        return log_oom();
                        }
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, fields);

                        return 1;
                } else if (contents[0] == SD_BUS_TYPE_BYTE &&
                           STR_IN_SET(name,
                                      "CPUAffinity", "NUMAMask", "AllowedCPUs", "AllowedMemoryNodes",
                                      "EffectiveCPUs", "EffectiveMemoryNodes")) {

                        _cleanup_free_ char *affinity = NULL;
                        _cleanup_(cpu_set_reset) CPUSet set = {};
                        const void *a;
                        size_t n;

                        r = sd_bus_message_read_array(m, 'y', &a, &n);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = cpu_set_from_dbus(a, n, &set);
                        if (r < 0)
                                return log_error_errno(r, "Failed to deserialize %s: %m", name);

                        affinity = cpu_set_to_range_string(&set);
                        if (!affinity)
                                return log_oom();

                        bus_print_property_value(name, expected_value, flags, affinity);

                        return 1;
                } else if (streq(name, "MountImages")) {
                        _cleanup_free_ char *paths = NULL;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ssba(ss))");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        for (;;) {
                                _cleanup_free_ char *str = NULL;
                                const char *source, *destination, *partition, *mount_options;
                                int ignore_enoent;

                                r = sd_bus_message_enter_container(m, 'r', "ssba(ss)");
                                if (r < 0)
                                        return bus_log_parse_error(r);
                                if (r == 0)
                                        break;

                                r = sd_bus_message_read(m, "ssb", &source, &destination, &ignore_enoent);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                str = strjoin(ignore_enoent ? "-" : "",
                                              source,
                                              ":",
                                              destination);
                                if (!str)
                                        return log_oom();

                                r = sd_bus_message_enter_container(m, 'a', "(ss)");
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                while ((r = sd_bus_message_read(m, "(ss)", &partition, &mount_options)) > 0)
                                        if (!strextend_with_separator(&str, ":", partition, mount_options))
                                                return log_oom();
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                if (!strextend_with_separator(&paths, " ", str))
                                        return log_oom();

                                r = sd_bus_message_exit_container(m);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = sd_bus_message_exit_container(m);
                                if (r < 0)
                                        return bus_log_parse_error(r);
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, paths);

                        return 1;

                } else if (streq(name, "ExtensionImages")) {
                        _cleanup_free_ char *paths = NULL;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sba(ss))");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        for (;;) {
                                _cleanup_free_ char *str = NULL;
                                const char *source, *partition, *mount_options;
                                int ignore_enoent;

                                r = sd_bus_message_enter_container(m, 'r', "sba(ss)");
                                if (r < 0)
                                        return bus_log_parse_error(r);
                                if (r == 0)
                                        break;

                                r = sd_bus_message_read(m, "sb", &source, &ignore_enoent);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                str = strjoin(ignore_enoent ? "-" : "", source);
                                if (!str)
                                        return log_oom();

                                r = sd_bus_message_enter_container(m, 'a', "(ss)");
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                while ((r = sd_bus_message_read(m, "(ss)", &partition, &mount_options)) > 0)
                                        if (!strextend_with_separator(&str, ":", partition, mount_options))
                                                return log_oom();
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                if (!strextend_with_separator(&paths, " ", str))
                                        return log_oom();

                                r = sd_bus_message_exit_container(m);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                r = sd_bus_message_exit_container(m);
                                if (r < 0)
                                        return bus_log_parse_error(r);
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        bus_print_property_value(name, expected_value, flags, paths);

                        return 1;

                } else if (streq(name, "BPFProgram")) {
                        const char *a, *p;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(ss)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(ss)", &a, &p)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s:%s", a, p);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;
                } else if (STR_IN_SET(name, "SocketBindAllow", "SocketBindDeny")) {
                        uint16_t nr_ports, port_min;
                        int32_t af, ip_protocol;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(iiqq)");
                        if (r < 0)
                                return bus_log_parse_error(r);
                        while ((r = sd_bus_message_read(m, "(iiqq)", &af, &ip_protocol, &nr_ports, &port_min)) > 0) {
                                const char *family, *colon1, *protocol = "", *colon2 = "";

                                family = strempty(af_to_ipv4_ipv6(af));
                                colon1 = isempty(family) ? "" : ":";

                                if (ip_protocol != 0) {
                                        protocol = ip_protocol_to_tcp_udp(ip_protocol);
                                        colon2 = "";
                                }

                                if (nr_ports == 0)
                                        bus_print_property_valuef(name, expected_value, flags, "%s%s%s%sany",
                                                        family, colon1, protocol, colon2);
                                else if (nr_ports == 1)
                                        bus_print_property_valuef(
                                                        name, expected_value, flags, "%s%s%s%s%hu",
                                                        family, colon1, protocol, colon2, port_min);
                                else
                                        bus_print_property_valuef(
                                                        name, expected_value, flags, "%s%s%s%s%hu-%hu",
                                                        family, colon1, protocol, colon2, port_min,
                                                        (uint16_t) (port_min + nr_ports - 1));
                        }
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;
                } else if (STR_IN_SET(name, "StateDirectorySymlink", "RuntimeDirectorySymlink", "CacheDirectorySymlink", "LogsDirectorySymlink")) {
                        const char *a, *p;
                        uint64_t symlink_flags;

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sst)");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        while ((r = sd_bus_message_read(m, "(sst)", &a, &p, &symlink_flags)) > 0)
                                bus_print_property_valuef(name, expected_value, flags, "%s:%s", a, p);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        return 1;
                }

                break;
        }

        return 0;
}

typedef enum SystemctlShowMode{
        SYSTEMCTL_SHOW_PROPERTIES,
        SYSTEMCTL_SHOW_STATUS,
        SYSTEMCTL_SHOW_HELP,
        _SYSTEMCTL_SHOW_MODE_MAX,
        _SYSTEMCTL_SHOW_MODE_INVALID = -EINVAL,
} SystemctlShowMode;

static const char* const systemctl_show_mode_table[_SYSTEMCTL_SHOW_MODE_MAX] = {
        [SYSTEMCTL_SHOW_PROPERTIES] = "show",
        [SYSTEMCTL_SHOW_STATUS] = "status",
        [SYSTEMCTL_SHOW_HELP] = "help",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(systemctl_show_mode, SystemctlShowMode);

static int show_one(
                sd_bus *bus,
                const char *path,
                const char *unit,
                SystemctlShowMode show_mode,
                bool *new_line,
                bool *ellipsized) {

        static const struct bus_properties_map property_map[] = {
                { "LoadState",                      "s",               NULL,           offsetof(UnitStatusInfo, load_state)                        },
                { "ActiveState",                    "s",               NULL,           offsetof(UnitStatusInfo, active_state)                      },
                { "FreezerState",                   "s",               NULL,           offsetof(UnitStatusInfo, freezer_state)                     },
                { "Documentation",                  "as",              NULL,           offsetof(UnitStatusInfo, documentation)                     },
                {}
        }, status_map[] = {
                { "Id",                             "s",               NULL,           offsetof(UnitStatusInfo, id)                                },
                { "LoadState",                      "s",               NULL,           offsetof(UnitStatusInfo, load_state)                        },
                { "ActiveState",                    "s",               NULL,           offsetof(UnitStatusInfo, active_state)                      },
                { "FreezerState",                   "s",               NULL,           offsetof(UnitStatusInfo, freezer_state)                     },
                { "SubState",                       "s",               NULL,           offsetof(UnitStatusInfo, sub_state)                         },
                { "UnitFileState",                  "s",               NULL,           offsetof(UnitStatusInfo, unit_file_state)                   },
                { "UnitFilePreset",                 "s",               NULL,           offsetof(UnitStatusInfo, unit_file_preset)                  },
                { "Description",                    "s",               NULL,           offsetof(UnitStatusInfo, description)                       },
                { "Following",                      "s",               NULL,           offsetof(UnitStatusInfo, following)                         },
                { "Documentation",                  "as",              NULL,           offsetof(UnitStatusInfo, documentation)                     },
                { "FragmentPath",                   "s",               NULL,           offsetof(UnitStatusInfo, fragment_path)                     },
                { "SourcePath",                     "s",               NULL,           offsetof(UnitStatusInfo, source_path)                       },
                { "ControlGroup",                   "s",               NULL,           offsetof(UnitStatusInfo, control_group)                     },
                { "DropInPaths",                    "as",              NULL,           offsetof(UnitStatusInfo, dropin_paths)                      },
                { "LoadError",                      "(ss)",            map_load_error, offsetof(UnitStatusInfo, load_error)                        },
                { "Result",                         "s",               NULL,           offsetof(UnitStatusInfo, result)                            },
                { "TriggeredBy",                    "as",              NULL,           offsetof(UnitStatusInfo, triggered_by)                      },
                { "Triggers",                       "as",              NULL,           offsetof(UnitStatusInfo, triggers)                          },
                { "InactiveExitTimestamp",          "t",               NULL,           offsetof(UnitStatusInfo, inactive_exit_timestamp)           },
                { "InactiveExitTimestampMonotonic", "t",               NULL,           offsetof(UnitStatusInfo, inactive_exit_timestamp_monotonic) },
                { "ActiveEnterTimestamp",           "t",               NULL,           offsetof(UnitStatusInfo, active_enter_timestamp)            },
                { "ActiveExitTimestamp",            "t",               NULL,           offsetof(UnitStatusInfo, active_exit_timestamp)             },
                { "RuntimeMaxUSec",                 "t",               NULL,           offsetof(UnitStatusInfo, runtime_max_sec)                   },
                { "InactiveEnterTimestamp",         "t",               NULL,           offsetof(UnitStatusInfo, inactive_enter_timestamp)          },
                { "NeedDaemonReload",               "b",               NULL,           offsetof(UnitStatusInfo, need_daemon_reload)                },
                { "Transient",                      "b",               NULL,           offsetof(UnitStatusInfo, transient)                         },
                { "ExecMainPID",                    "u",               NULL,           offsetof(UnitStatusInfo, main_pid)                          },
                { "MainPID",                        "u",               map_main_pid,   0                                                           },
                { "ControlPID",                     "u",               NULL,           offsetof(UnitStatusInfo, control_pid)                       },
                { "StatusText",                     "s",               NULL,           offsetof(UnitStatusInfo, status_text)                       },
                { "PIDFile",                        "s",               NULL,           offsetof(UnitStatusInfo, pid_file)                          },
                { "StatusErrno",                    "i",               NULL,           offsetof(UnitStatusInfo, status_errno)                      },
                { "ExecMainStartTimestamp",         "t",               NULL,           offsetof(UnitStatusInfo, start_timestamp)                   },
                { "ExecMainExitTimestamp",          "t",               NULL,           offsetof(UnitStatusInfo, exit_timestamp)                    },
                { "ExecMainCode",                   "i",               NULL,           offsetof(UnitStatusInfo, exit_code)                         },
                { "ExecMainStatus",                 "i",               NULL,           offsetof(UnitStatusInfo, exit_status)                       },
                { "LogNamespace",                   "s",               NULL,           offsetof(UnitStatusInfo, log_namespace)                     },
                { "ConditionTimestamp",             "t",               NULL,           offsetof(UnitStatusInfo, condition_timestamp)               },
                { "ConditionResult",                "b",               NULL,           offsetof(UnitStatusInfo, condition_result)                  },
                { "Conditions",                     "a(sbbsi)",        map_conditions, 0                                                           },
                { "AssertTimestamp",                "t",               NULL,           offsetof(UnitStatusInfo, assert_timestamp)                  },
                { "AssertResult",                   "b",               NULL,           offsetof(UnitStatusInfo, assert_result)                     },
                { "Asserts",                        "a(sbbsi)",        map_asserts,    0                                                           },
                { "NextElapseUSecRealtime",         "t",               NULL,           offsetof(UnitStatusInfo, next_elapse_real)                  },
                { "NextElapseUSecMonotonic",        "t",               NULL,           offsetof(UnitStatusInfo, next_elapse_monotonic)             },
                { "NAccepted",                      "u",               NULL,           offsetof(UnitStatusInfo, n_accepted)                        },
                { "NConnections",                   "u",               NULL,           offsetof(UnitStatusInfo, n_connections)                     },
                { "NRefused",                       "u",               NULL,           offsetof(UnitStatusInfo, n_refused)                         },
                { "Accept",                         "b",               NULL,           offsetof(UnitStatusInfo, accept)                            },
                { "Listen",                         "a(ss)",           map_listen,     offsetof(UnitStatusInfo, listen)                            },
                { "SysFSPath",                      "s",               NULL,           offsetof(UnitStatusInfo, sysfs_path)                        },
                { "Where",                          "s",               NULL,           offsetof(UnitStatusInfo, where)                             },
                { "What",                           "s",               NULL,           offsetof(UnitStatusInfo, what)                              },
                { "MemoryCurrent",                  "t",               NULL,           offsetof(UnitStatusInfo, memory_current)                    },
                { "MemoryAvailable",                "t",               NULL,           offsetof(UnitStatusInfo, memory_available)                  },
                { "DefaultMemoryMin",               "t",               NULL,           offsetof(UnitStatusInfo, default_memory_min)                },
                { "DefaultMemoryLow",               "t",               NULL,           offsetof(UnitStatusInfo, default_memory_low)                },
                { "MemoryMin",                      "t",               NULL,           offsetof(UnitStatusInfo, memory_min)                        },
                { "MemoryLow",                      "t",               NULL,           offsetof(UnitStatusInfo, memory_low)                        },
                { "MemoryHigh",                     "t",               NULL,           offsetof(UnitStatusInfo, memory_high)                       },
                { "MemoryMax",                      "t",               NULL,           offsetof(UnitStatusInfo, memory_max)                        },
                { "MemorySwapMax",                  "t",               NULL,           offsetof(UnitStatusInfo, memory_swap_max)                   },
                { "MemoryLimit",                    "t",               NULL,           offsetof(UnitStatusInfo, memory_limit)                      },
                { "CPUUsageNSec",                   "t",               NULL,           offsetof(UnitStatusInfo, cpu_usage_nsec)                    },
                { "TasksCurrent",                   "t",               NULL,           offsetof(UnitStatusInfo, tasks_current)                     },
                { "TasksMax",                       "t",               NULL,           offsetof(UnitStatusInfo, tasks_max)                         },
                { "IPIngressBytes",                 "t",               NULL,           offsetof(UnitStatusInfo, ip_ingress_bytes)                  },
                { "IPEgressBytes",                  "t",               NULL,           offsetof(UnitStatusInfo, ip_egress_bytes)                   },
                { "IOReadBytes",                    "t",               NULL,           offsetof(UnitStatusInfo, io_read_bytes)                     },
                { "IOWriteBytes",                   "t",               NULL,           offsetof(UnitStatusInfo, io_write_bytes)                    },
                { "ExecCondition",                  "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecConditionEx",                "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecStartPre",                   "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStartPreEx",                 "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecStart",                      "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStartEx",                    "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecStartPost",                  "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStartPostEx",                "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecReload",                     "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecReloadEx",                   "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecStopPre",                    "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStop",                       "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStopEx",                     "a(sasasttttuii)", map_exec,       0                                                           },
                { "ExecStopPost",                   "a(sasbttttuii)",  map_exec,       0                                                           },
                { "ExecStopPostEx",                 "a(sasasttttuii)", map_exec,       0                                                           },
                {}
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_set_free_ Set *found_properties = NULL;
        _cleanup_(unit_status_info_free) UnitStatusInfo info = {
                .memory_current = UINT64_MAX,
                .memory_high = CGROUP_LIMIT_MAX,
                .memory_max = CGROUP_LIMIT_MAX,
                .memory_swap_max = CGROUP_LIMIT_MAX,
                .memory_limit = UINT64_MAX,
                .memory_available = CGROUP_LIMIT_MAX,
                .cpu_usage_nsec = UINT64_MAX,
                .tasks_current = UINT64_MAX,
                .tasks_max = UINT64_MAX,
                .ip_ingress_bytes = UINT64_MAX,
                .ip_egress_bytes = UINT64_MAX,
                .io_read_bytes = UINT64_MAX,
                .io_write_bytes = UINT64_MAX,
        };
        int r;

        assert(path);
        assert(new_line);

        log_debug("Showing one %s", path);

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        show_mode == SYSTEMCTL_SHOW_STATUS ? status_map : property_map,
                        BUS_MAP_BOOLEAN_AS_BOOL,
                        &error,
                        &reply,
                        &info);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties: %s", bus_error_message(&error, r));

        if (unit && streq_ptr(info.load_state, "not-found") && streq_ptr(info.active_state, "inactive")) {
                log_full(show_mode == SYSTEMCTL_SHOW_PROPERTIES ? LOG_DEBUG : LOG_ERR,
                         "Unit %s could not be found.", unit);

                if (show_mode == SYSTEMCTL_SHOW_STATUS)
                        return EXIT_PROGRAM_OR_SERVICES_STATUS_UNKNOWN;
                if (show_mode == SYSTEMCTL_SHOW_HELP)
                        return -ENOENT;
        }

        if (*new_line)
                printf("\n");

        *new_line = true;

        if (show_mode == SYSTEMCTL_SHOW_STATUS) {
                print_status_info(bus, &info, ellipsized);

                if (info.active_state && !STR_IN_SET(info.active_state, "active", "reloading"))
                        return EXIT_PROGRAM_NOT_RUNNING;

                return EXIT_PROGRAM_RUNNING_OR_SERVICE_OK;

        } else if (show_mode == SYSTEMCTL_SHOW_HELP) {
                show_unit_help(&info);
                return 0;
        }

        r = sd_bus_message_rewind(reply, true);
        if (r < 0)
                return log_error_errno(r, "Failed to rewind: %s", bus_error_message(&error, r));

        r = bus_message_print_all_properties(reply, print_property, arg_properties, arg_print_flags, &found_properties);
        if (r < 0)
                return bus_log_parse_error(r);

        STRV_FOREACH(pp, arg_properties)
                if (!set_contains(found_properties, *pp))
                        log_debug("Property %s does not exist.", *pp);

        return 0;
}

static int get_unit_dbus_path_by_pid(
                sd_bus *bus,
                uint32_t pid,
                char **unit) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        char *u;
        int r;

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPID", &error, &reply, "u", pid);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit for PID %"PRIu32": %s", pid, bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &u);
        if (r < 0)
                return bus_log_parse_error(r);

        u = strdup(u);
        if (!u)
                return log_oom();

        *unit = u;
        return 0;
}

static int show_all(
                sd_bus *bus,
                SystemctlShowMode show_mode,
                bool *new_line,
                bool *ellipsized) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        unsigned c;
        int r, ret = 0;

        r = get_unit_list(bus, NULL, NULL, &unit_infos, 0, &reply);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        c = (unsigned) r;

        typesafe_qsort(unit_infos, c, unit_info_compare);

        for (const UnitInfo *u = unit_infos; u < unit_infos + c; u++) {
                _cleanup_free_ char *p = NULL;

                p = unit_dbus_path_from_name(u->id);
                if (!p)
                        return log_oom();

                r = show_one(bus, p, u->id, show_mode, new_line, ellipsized);
                if (r < 0)
                        return r;
                if (r > 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

static int show_system_status(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(machine_info_clear) struct machine_info mi = {};
        static const char prefix[] = "           ";
        _cleanup_free_ char *hn = NULL;
        const char *on, *off;
        unsigned c;
        int r;

        hn = gethostname_malloc();
        if (!hn)
                return log_oom();

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        machine_info_property_map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        &mi);
        if (r < 0)
                return log_error_errno(r, "Failed to read server status: %s", bus_error_message(&error, r));

        if (streq_ptr(mi.state, "degraded")) {
                on = ansi_highlight_red();
                off = ansi_normal();
        } else if (streq_ptr(mi.state, "running")) {
                on = ansi_highlight_green();
                off = ansi_normal();
        } else {
                on = ansi_highlight_yellow();
                off = ansi_normal();
        }

        printf("%s%s%s %s\n", on, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE), off, arg_host ?: hn);

        printf("    State: %s%s%s\n",
               on, strna(mi.state), off);

        printf("    Units: %" PRIu32 " loaded (incl. loaded aliases)\n", mi.n_names);
        printf("     Jobs: %" PRIu32 " queued\n", mi.n_jobs);
        printf("   Failed: %" PRIu32 " units\n", mi.n_failed_units);

        printf("    Since: %s; %s\n",
               FORMAT_TIMESTAMP_STYLE(mi.timestamp, arg_timestamp_style),
               FORMAT_TIMESTAMP_RELATIVE(mi.timestamp));

        printf("  systemd: %s\n", mi.version);

        if (!isempty(mi.tainted))
                printf("  Tainted: %s%s%s\n", ansi_highlight_yellow(), mi.tainted, ansi_normal());

        printf("   CGroup: %s\n", empty_to_root(mi.control_group));

        c = LESS_BY(columns(), strlen(prefix));

        r = unit_show_processes(bus, SPECIAL_ROOT_SLICE, mi.control_group, prefix, c, get_output_flags(), &error);
        if (r == -EBADR && arg_transport == BUS_TRANSPORT_LOCAL) /* Compatibility for really old systemd versions */
                show_cgroup(SYSTEMD_CGROUP_CONTROLLER, strempty(mi.control_group), prefix, c, get_output_flags());
        else if (r < 0)
                log_warning_errno(r, "Failed to dump process list for '%s', ignoring: %s",
                                  arg_host ?: hn, bus_error_message(&error, r));

        return 0;
}

int verb_show(int argc, char *argv[], void *userdata) {
        bool new_line = false, ellipsized = false;
        SystemctlShowMode show_mode;
        int r, ret = 0;
        sd_bus *bus;

        assert(argv);

        show_mode = systemctl_show_mode_from_string(argv[0]);
        if (show_mode < 0)
                return log_error_errno(show_mode, "Invalid argument '%s'.", argv[0]);

        if (show_mode == SYSTEMCTL_SHOW_HELP && argc <= 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'help' command expects one or more unit names.\n"
                                       "(Alternatively, help for systemctl itself may be shown with --help)");

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        if (argc <= 1) {
                /* If no argument or filter is specified inspect the manager itself:
                 * systemctl status → we show status of the manager
                 * systemctl status --all → status of the manager + status of all units
                 * systemctl status --state=… → status of units in listed states
                 * systemctl status --type=… → status of units of listed types
                 * systemctl status --failed → status of failed units, mirroring systemctl list-units --failed
                 */

                if (!arg_states && !arg_types) {
                        if (show_mode == SYSTEMCTL_SHOW_PROPERTIES)
                                /* systemctl show --all → show properties of the manager */
                                return show_one(bus, "/org/freedesktop/systemd1", NULL, show_mode, &new_line, &ellipsized);

                        r = show_system_status(bus);
                        if (r < 0)
                                return r;

                        new_line = true;
                }

                if (arg_all || arg_states || arg_types)
                        ret = show_all(bus, show_mode, &new_line, &ellipsized);
        } else {
                _cleanup_free_ char **patterns = NULL;

                STRV_FOREACH(name, strv_skip(argv, 1)) {
                        _cleanup_free_ char *path = NULL, *unit = NULL;
                        uint32_t id;

                        if (safe_atou32(*name, &id) < 0) {
                                if (strv_push(&patterns, *name) < 0)
                                        return log_oom();

                                continue;
                        } else if (show_mode == SYSTEMCTL_SHOW_PROPERTIES) {
                                /* Interpret as job id */
                                if (asprintf(&path, "/org/freedesktop/systemd1/job/%u", id) < 0)
                                        return log_oom();

                        } else {
                                /* Interpret as PID */
                                r = get_unit_dbus_path_by_pid(bus, id, &path);
                                if (r < 0) {
                                        ret = r;
                                        continue;
                                }

                                r = unit_name_from_dbus_path(path, &unit);
                                if (r < 0)
                                        return log_oom();
                        }

                        r = show_one(bus, path, unit, show_mode, &new_line, &ellipsized);
                        if (r < 0)
                                return r;
                        if (r > 0 && ret == 0)
                                ret = r;
                }

                if (!strv_isempty(patterns)) {
                        _cleanup_strv_free_ char **names = NULL;

                        r = expand_unit_names(bus, patterns, NULL, &names, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to expand names: %m");

                        r = maybe_extend_with_unit_dependencies(bus, &names);
                        if (r < 0)
                                return r;

                        STRV_FOREACH(name, names) {
                                _cleanup_free_ char *path = NULL;

                                path = unit_dbus_path_from_name(*name);
                                if (!path)
                                        return log_oom();

                                r = show_one(bus, path, *name, show_mode, &new_line, &ellipsized);
                                if (r < 0)
                                        return r;
                                if (r > 0 && ret == 0)
                                        ret = r;
                        }
                }
        }

        if (ellipsized && !arg_quiet)
                printf("Hint: Some lines were ellipsized, use -l to show in full.\n");

        return ret;
}
