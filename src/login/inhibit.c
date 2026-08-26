/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "verbs.h"

static const char *arg_what = NULL;
static const char *arg_who = NULL;
static const char *arg_why = NULL;
static const char *arg_mode = NULL;
static int arg_signal = SIGNO_INVALID;
static bool arg_ask_password = true;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

static enum {
        ACTION_INHIBIT,
        ACTION_LIST
} arg_action = ACTION_INHIBIT;

COMMAND(
        "systemd-inhibit\0",
        "Execute a process while inhibiting shutdown/sleep/idle.",
        .argspec =
                "COMMAND…\0"
                "--list\0",
        .man_pages = "systemd-inhibit(1)\0",
        .pager_flags = &arg_pager_flags,
);

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

typedef struct Context {
        PidRef *child;      /* The command we are wrapping... */
        const char *name;   /* ...and how to call it in log messages */
} Context;

static int on_prepare_for(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        Context *c = ASSERT_PTR(userdata);
        int b, r;

        assert(message);
        assert(pidref_is_set(c->child));

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }
        if (!b)
                /* We are resuming, so nothing to do */
                return 0;

        const char *operation = streq_ptr(sd_bus_message_get_member(message), "PrepareForShutdown") ?
                "shut down" : "sleep";

        log_info("Forwarding SIG%s to '%s', because the system is about to %s.",
                 signal_to_string(arg_signal), c->name, operation);

        r = pidref_kill(c->child, arg_signal);
        if (r < 0)
                log_warning_errno(r, "Failed to send SIG%s to '%s', ignoring: %m",
                                  signal_to_string(arg_signal), c->name);

        return 0;
}

static int subscribe_prepare_for(sd_bus *bus, const char *member, Context *context, sd_bus_slot **ret_slot) {
        int r;

        assert(bus);
        assert(member);
        assert(context);
        assert(ret_slot);

        r = bus_match_signal(bus, ret_slot, bus_login_mgr, member, on_prepare_for, context);
        if (r < 0)
                return log_error_errno(r, "Failed to subscribe to %s signal: %m", member);

        return 0;
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

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("what", "WHAT",
                            "Operations to inhibit, colon separated list "
                            "(shutdown, sleep, idle, handle-power-key, "
                            "handle-suspend-key, handle-hibernate-key, "
                            "handle-lid-switch)"):
                        arg_what = opts.arg;
                        break;

                OPTION_LONG("who", "STRING",
                            "A descriptive string who is inhibiting"):
                        arg_who = opts.arg;
                        break;

                OPTION_LONG("why", "STRING",
                            "A descriptive string why is being inhibited"):
                        arg_why = opts.arg;
                        break;

                OPTION_LONG("mode", "MODE", "One of block, block-weak, or delay"):
                        arg_mode = opts.arg;
                        break;

                OPTION_LONG("signal", "SIGNAL",
                            "Signal to send to the command once the delayed operation "
                            "is about to be executed (requires --mode=delay)"):
                        r = parse_signal_argument(opts.arg, &arg_signal);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("list", NULL, "List active inhibitors"):
                        arg_action = ACTION_LIST;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
                }

        char **args = option_parser_get_args(&opts);

        if (arg_action == ACTION_INHIBIT && strv_isempty(args))
                arg_action = ACTION_LIST;

        if (SIGNAL_VALID(arg_signal)) {
                if (arg_action != ACTION_INHIBIT)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--signal= requires a command to execute.");

                if (!streq_ptr(arg_mode, "delay"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--signal= is only supported with --mode=delay.");
        }

        *remaining_args = args;
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
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
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                _cleanup_strv_free_ char **arguments = NULL;
                _cleanup_free_ char *w = NULL;
                _cleanup_close_ int fd = -EBADF;

                /* Ignore SIGINT and allow the forked process to receive it */
                (void) ignore_signals(SIGINT);

                if (!arg_what)
                        arg_what = "idle:sleep:shutdown";

                if (!arg_who) {
                        w = strv_join(args, " ");
                        if (!w)
                                return log_oom();

                        arg_who = w;
                }

                if (!arg_why)
                        arg_why = "Unknown reason";

                if (!arg_mode)
                        arg_mode = "block";

                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                Context context = {
                        .child = &pidref,
                        .name = args[0],
                };
                _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *sleep_slot = NULL, *shutdown_slot = NULL;

                if (SIGNAL_VALID(arg_signal)) {
                        r = default_signals(SIGCHLD);
                        if (r < 0)
                                return log_error_errno(r, "Failed to reset SIGCHLD: %m");

                        r = sd_event_new(&event);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate event loop: %m");

                        /* Should be before locking so that we cannot miss a notification race */
                        if (string_contains_word(arg_what, ":", "sleep")) {
                                r = subscribe_prepare_for(bus, "PrepareForSleep", &context, &sleep_slot);
                                if (r < 0)
                                        return r;
                        }

                        if (string_contains_word(arg_what, ":", "shutdown")) {
                                r = subscribe_prepare_for(bus, "PrepareForShutdown", &context, &shutdown_slot);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to attach bus to event loop: %m");
                }

                fd = inhibit(bus, &error);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to inhibit: %s", bus_error_message(&error, fd));

                arguments = strv_copy(args);
                if (!arguments)
                        return log_oom();

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

                if (event) {
                        _cleanup_(sd_event_source_unrefp) sd_event_source *child_source = NULL;

                        /* The command is already running at this point, so on failure just stop
                         * forwarding signals and go wait for it, rather than taking it down with us. */

                        r = event_add_child_pidref(event, &child_source, &pidref, WEXITED|WNOWAIT,
                                                   /* callback= */ NULL, /* userdata= */ NULL);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate child event source, no longer forwarding SIG%s: %m",
                                                  signal_to_string(arg_signal));
                        else {
                                r = sd_event_loop(event);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to run event loop, no longer forwarding SIG%s: %m",
                                                          signal_to_string(arg_signal));
                        }
                }

                return pidref_wait_for_terminate_and_check(args[0], &pidref, WAIT_LOG_ABNORMAL);
        }
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
