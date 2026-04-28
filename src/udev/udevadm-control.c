/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>
#include <string.h>

#include "creds-util.h"
#include "errno-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "udev-ctrl.h"
#include "udev-varlink.h"
#include "udevadm.h"
#include "varlink-util.h"
#include "virt.h"

static char **arg_env = NULL;
static usec_t arg_timeout = 60 * USEC_PER_SEC;
static bool arg_ping = false;
static bool arg_reload = false;
static bool arg_exit = false;
static int arg_max_children = -1;
static int arg_log_level = -1;
static int arg_start_exec_queue = -1;
static int arg_trace = -1;
static bool arg_revert = false;
static bool arg_load_credentials = false;

STATIC_DESTRUCTOR_REGISTER(arg_env, strv_freep);

static bool arg_has_control_commands(void) {
        return
                arg_exit ||
                arg_log_level >= 0 ||
                arg_start_exec_queue >= 0 ||
                arg_reload ||
                !strv_isempty(arg_env) ||
                arg_max_children >= 0 ||
                arg_ping ||
                arg_trace >= 0 ||
                arg_revert;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-control", &options);
        if (r < 0)
                return r;

        help_cmdline("control OPTION");
        help_abstract("Control the udev daemon.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "udevadm-control" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_NAMESPACE("udevadm-control"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('e', "exit", NULL, "Instruct the daemon to cleanup and exit"):
                        arg_exit = true;
                        break;

                OPTION_LONG("log-priority", "LEVEL", NULL): {} /* backward compat alias for --log-level */
                OPTION('l', "log-level", "LEVEL", "Set the udev log level for the daemon"):
                        arg_log_level = log_level_from_string(opts.arg);
                        if (arg_log_level < 0)
                                return log_error_errno(arg_log_level, "Failed to parse log level '%s': %m", opts.arg);
                        break;

                OPTION('s', "stop-exec-queue", NULL, "Do not execute events, queue only"):
                        arg_start_exec_queue = false;
                        break;

                OPTION('S', "start-exec-queue", NULL, "Execute events, flush queue"):
                        arg_start_exec_queue = true;
                        break;

                OPTION_LONG("reload-rules", NULL, NULL): {} /* hidden alias for -R */
                OPTION('R', "reload", NULL, "Reload rules and databases"):
                        arg_reload = true;
                        break;

                OPTION_LONG("env", "KEY=VALUE", NULL): {} /* hidden alias for -p */
                OPTION('p', "property", "KEY=VALUE", "Set a global property for all events"):
                        if (!strchr(opts.arg, '='))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "expect <KEY>=<value> instead of '%s'", opts.arg);

                        r = strv_extend(&arg_env, opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extend environment: %m");

                        break;

                OPTION('m', "children-max", "N", "Maximum number of children"): {
                        unsigned i;
                        r = safe_atou(opts.arg, &i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse maximum number of children '%s': %m", opts.arg);
                        arg_max_children = i;
                        break;
                }

                OPTION_LONG("ping", NULL, "Wait for udev to respond to a ping message"):
                        arg_ping = true;
                        break;

                OPTION_LONG("trace", "BOOL", "Enable/disable trace logging"):
                        r = parse_boolean_argument("--trace=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        arg_trace = r;
                        break;

                OPTION_LONG("revert", NULL, "Revert previously set configurations"):
                        arg_revert = true;
                        break;

                OPTION('t', "timeout", "SECONDS", "Maximum time to block for a reply"):
                        r = parse_sec(opts.arg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", opts.arg);
                        break;

                OPTION_LONG("load-credentials", NULL, "Load udev rules from credentials"):
                        arg_load_credentials = true;
                        break;
                }

        if (!arg_has_control_commands() && !arg_load_credentials)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No control command option is specified.");

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This subprogram takes no positional arguments.");

        return 1;
}

static int send_control_commands_via_ctrl(void) {
        _cleanup_(udev_ctrl_unrefp) UdevCtrl *uctrl = NULL;
        int r;

        r = udev_ctrl_new(&uctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev control: %m");

        if (arg_exit) {
                r = udev_ctrl_send_exit(uctrl);
                if (r < 0)
                       return log_error_errno(r, "Failed to send exit request: %m");
                return 0;
        }

        if (arg_log_level >= 0) {
                r = udev_ctrl_send_set_log_level(uctrl, arg_log_level);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set log level: %m");
        }

        if (arg_start_exec_queue == false) {
                r = udev_ctrl_send_stop_exec_queue(uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to stop exec queue: %m");
        }

        if (arg_start_exec_queue == true) {
                r = udev_ctrl_send_start_exec_queue(uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to start exec queue: %m");
        }

        if (arg_reload) {
                r = udev_ctrl_send_reload(uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send reload request: %m");
        }

        STRV_FOREACH(env, arg_env) {
                r = udev_ctrl_send_set_env(uctrl, *env);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to update environment: %m");
        }

        if (arg_max_children >= 0) {
                r = udev_ctrl_send_set_children_max(uctrl, arg_max_children);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set number of children: %m");
        }

        if (arg_ping) {
                r = udev_ctrl_send_ping(uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send a ping message: %m");
        }

        r = udev_ctrl_wait(uctrl, arg_timeout);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for daemon to reply: %m");

        return 0;
}

static int send_control_commands(void) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        r = udev_varlink_connect(&link, arg_timeout);
        if (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT) {
                log_debug_errno(r, "Failed to connect to udev via varlink, falling back to use legacy control socket, ignoring: %m");
                return send_control_commands_via_ctrl();
        }
        if (r < 0)
                return log_error_errno(r, "Failed to connect to udev via varlink: %m");

        if (arg_exit)
                return varlink_call_and_log(link, "io.systemd.Udev.Exit", /* parameters= */ NULL, /* reply= */ NULL);

        if (arg_revert) {
                r = varlink_call_and_log(link, "io.systemd.Udev.Revert", /* parameters= */ NULL, /* reply= */ NULL);
                if (r < 0)
                        return r;
        }

        if (arg_log_level >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.service.SetLogLevel", /* reply= */ NULL,
                                           SD_JSON_BUILD_PAIR_INTEGER("level", arg_log_level));
                if (r < 0)
                        return r;
        }

        if (arg_start_exec_queue >= 0) {
                r = varlink_call_and_log(link, arg_start_exec_queue ? "io.systemd.Udev.StartExecQueue" : "io.systemd.Udev.StopExecQueue",
                                         /* parameters= */ NULL, /* reply= */ NULL);
                if (r < 0)
                        return r;
        }

        if (arg_reload) {
                r = varlink_call_and_log(link, "io.systemd.service.Reload", /* parameters= */ NULL, /* reply= */ NULL);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(arg_env)) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetEnvironment", /* reply= */ NULL,
                                           SD_JSON_BUILD_PAIR_STRV("assignments", arg_env));
                if (r < 0)
                        return r;
        }

        if (arg_max_children >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetChildrenMax", /* reply= */ NULL,
                                           SD_JSON_BUILD_PAIR_UNSIGNED("number", arg_max_children));
                if (r < 0)
                        return r;
        }

        if (arg_ping) {
                r = varlink_call_and_log(link, "io.systemd.service.Ping", /* parameters= */ NULL, /* reply= */ NULL);
                if (r < 0)
                        return r;
        }

        if (arg_trace >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetTrace", /* reply= */ NULL,
                                           SD_JSON_BUILD_PAIR_BOOLEAN("enable", arg_trace));
                if (r < 0)
                        return r;
        }

        return 0;
}

int verb_control_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_load_credentials) {
                static const PickUpCredential table[] = {
                        { "udev.conf.",  "/run/udev/udev.conf.d/", ".conf"  },
                        { "udev.rules.", "/run/udev/rules.d/",     ".rules" },
                };
                r = pick_up_credentials(table, ELEMENTSOF(table));
                if (r < 0)
                        return r;
        }

        if (arg_has_control_commands()) {
                r = send_control_commands();
                if (r < 0)
                        return r;
        }

        return 0;
}
