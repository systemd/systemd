/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"

static const char *arg_what = NULL;
static const char *arg_who = NULL;
static const char *arg_why = NULL;
static const char *arg_mode = NULL;
static bool arg_ask_password = true;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

static enum {
        ACTION_INHIBIT,
        ACTION_LIST
} arg_action = ACTION_INHIBIT;

#include "inhibit.args.inc"

static int inhibit(sd_bus *bus, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;
        int fd;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_login_mgr, "Inhibit", error, &reply, "ssss", arg_what, arg_who, arg_why, arg_mode);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_UNIX_FD, &fd);
        if (r < 0)
                return r;

        return RET_NERRNO(fcntl(fd, F_DUPFD_CLOEXEC, 3));
}

static int print_inhibitors(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_strv_free_ char **what_filter = NULL;

        int r;

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_login_mgr, "ListInhibitors", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not get active inhibitors: %s", bus_error_message(&error, r));

        table = table_new("who", "uid", "user", "pid", "comm", "what", "why", "mode");
        if (!table)
                return log_oom();

        /* If there's not enough space, shorten the "WHY" column, as it's little more than an explaining comment. */
        (void) table_set_weight(table, TABLE_HEADER_CELL(6), 20);
        (void) table_set_maximum_width(table, TABLE_HEADER_CELL(0), columns()/2);

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssuu)");
        if (r < 0)
                return bus_log_parse_error(r);

        if (arg_what) {
                what_filter = strv_split(arg_what, ":");
                if (!what_filter)
                        return log_oom();
        }

        for (;;) {
                _cleanup_free_ char *comm = NULL, *u = NULL;
                const char *what, *who, *why, *mode;
                uint32_t uid, pid;

                r = sd_bus_message_read(reply, "(ssssuu)", &what, &who, &why, &mode, &uid, &pid);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (what_filter) {
                        bool skip = false;

                        STRV_FOREACH(op, what_filter)
                                if (!string_contains_word(what, ":", *op)) {
                                        skip = true;
                                        break;
                                }

                        if (skip)
                                continue;
                }

                if (arg_who && !streq(who, arg_who))
                        continue;

                if (arg_why && fnmatch(arg_why, why, FNM_CASEFOLD) != 0)
                        continue;

                if (arg_mode && !streq(mode, arg_mode))
                        continue;

                (void) pid_get_comm(pid, &comm);
                u = uid_to_name(uid);

                r = table_add_many(table,
                                   TABLE_STRING, who,
                                   TABLE_UID, (uid_t) uid,
                                   TABLE_STRING, strna(u),
                                   TABLE_PID, (pid_t) pid,
                                   TABLE_STRING, strna(comm),
                                   TABLE_STRING, what,
                                   TABLE_STRING, why,
                                   TABLE_STRING, mode);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!table_isempty(table)) {
                r = table_set_sort(table, (size_t) 1, (size_t) 0, (size_t) 5, (size_t) 6);
                if (r < 0)
                        return table_log_sort_error(r);

                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && !sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No inhibitors.\n");
                else
                        printf("\n%zu inhibitors listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-inhibit", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sExecute a process while inhibiting shutdown/sleep/idle.%s\n\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        if (arg_action == ACTION_INHIBIT && optind == argc)
                arg_action = ACTION_LIST;

        else if (arg_action == ACTION_INHIBIT && optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Missing command line to execute.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL, RUNTIME_SCOPE_SYSTEM);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        if (arg_action == ACTION_LIST)
                return print_inhibitors(bus);
        else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_strv_free_ char **arguments = NULL;
                _cleanup_free_ char *w = NULL;
                _cleanup_close_ int fd = -EBADF;

                /* Ignore SIGINT and allow the forked process to receive it */
                (void) ignore_signals(SIGINT);

                if (!arg_what)
                        arg_what = "idle:sleep:shutdown";

                if (!arg_who) {
                        w = strv_join(argv + optind, " ");
                        if (!w)
                                return log_oom();

                        arg_who = w;
                }

                if (!arg_why)
                        arg_why = "Unknown reason";

                if (!arg_mode)
                        arg_mode = "block";

                fd = inhibit(bus, &error);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to inhibit: %s", bus_error_message(&error, fd));

                arguments = strv_copy(argv + optind);
                if (!arguments)
                        return log_oom();

                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = pidref_safe_fork("(inhibit)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pidref);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */
                        execvp(arguments[0], arguments);
                        log_open();
                        log_error_errno(errno, "Failed to execute '%s': %m", arguments[0]);
                        _exit(EXIT_FAILURE);
                }

                return pidref_wait_for_terminate_and_check(argv[optind], &pidref, WAIT_LOG_ABNORMAL);
        }
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
