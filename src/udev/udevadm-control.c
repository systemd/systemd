/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "creds-util.h"
#include "errno-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "process-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "udevadm.h"
#include "udev-ctrl.h"
#include "udev-varlink.h"
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
                arg_trace >= 0;
}

static int help(void) {
        printf("%s control OPTION\n\n"
               "Control the udev daemon.\n\n"
               "  -h --help                Show this help\n"
               "  -V --version             Show package version\n"
               "  -e --exit                Instruct the daemon to cleanup and exit\n"
               "  -l --log-level=LEVEL     Set the udev log level for the daemon\n"
               "  -s --stop-exec-queue     Do not execute events, queue only\n"
               "  -S --start-exec-queue    Execute events, flush queue\n"
               "  -R --reload              Reload rules and databases\n"
               "  -p --property=KEY=VALUE  Set a global property for all events\n"
               "  -m --children-max=N      Maximum number of children\n"
               "     --ping                Wait for udev to respond to a ping message\n"
               "     --trace=BOOL          Enable/disable trace logging\n"
               "  -t --timeout=SECONDS     Maximum time to block for a reply\n"
               "     --load-credentials    Load udev rules from credentials\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PING = 0x100,
                ARG_TRACE,
                ARG_LOAD_CREDENTIALS,
        };

        static const struct option options[] = {
                { "exit",             no_argument,       NULL, 'e'                  },
                { "log-level",        required_argument, NULL, 'l'                  },
                { "log-priority",     required_argument, NULL, 'l'                  }, /* for backward compatibility */
                { "stop-exec-queue",  no_argument,       NULL, 's'                  },
                { "start-exec-queue", no_argument,       NULL, 'S'                  },
                { "reload",           no_argument,       NULL, 'R'                  },
                { "reload-rules",     no_argument,       NULL, 'R'                  }, /* alias for -R */
                { "property",         required_argument, NULL, 'p'                  },
                { "env",              required_argument, NULL, 'p'                  }, /* alias for -p */
                { "children-max",     required_argument, NULL, 'm'                  },
                { "ping",             no_argument,       NULL, ARG_PING             },
                { "trace",            required_argument, NULL, ARG_TRACE            },
                { "timeout",          required_argument, NULL, 't'                  },
                { "load-credentials", no_argument,       NULL, ARG_LOAD_CREDENTIALS },
                { "version",          no_argument,       NULL, 'V'                  },
                { "help",             no_argument,       NULL, 'h'                  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "el:sSRp:m:t:Vh", options, NULL)) >= 0)
                switch (c) {

                case 'e':
                        arg_exit = true;
                        break;

                case 'l':
                        arg_log_level = log_level_from_string(optarg);
                        if (arg_log_level < 0)
                                return log_error_errno(arg_log_level, "Failed to parse log level '%s': %m", optarg);
                        break;

                case 's':
                        arg_start_exec_queue = false;
                        break;

                case 'S':
                        arg_start_exec_queue = true;
                        break;

                case 'R':
                        arg_reload = true;
                        break;

                case 'p':
                        if (!strchr(optarg, '='))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "expect <KEY>=<value> instead of '%s'", optarg);

                        r = strv_extend(&arg_env, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extend environment: %m");

                        break;

                case 'm': {
                        unsigned i;
                        r = safe_atou(optarg, &i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse maximum number of children '%s': %m", optarg);
                        arg_max_children = i;
                        break;
                }

                case ARG_PING:
                        arg_ping = true;
                        break;

                case ARG_TRACE:
                        r = parse_boolean_argument("--trace=", optarg, NULL);
                        if (r < 0)
                                return r;

                        arg_trace = r;
                        break;

                case 't':
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                        break;

                case ARG_LOAD_CREDENTIALS:
                        arg_load_credentials = true;
                        break;

                case 'V':
                        return print_version();

                case 'h':
                        return help();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_has_control_commands() && !arg_load_credentials)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No control command option is specified.");

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous argument: %s", argv[optind]);

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
                return varlink_call_and_log(link, "io.systemd.Udev.Exit", /* parameters = */ NULL, /* reply = */ NULL);

        if (arg_log_level >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.service.SetLogLevel", /* reply = */ NULL,
                                           SD_JSON_BUILD_PAIR_INTEGER("level", arg_log_level));
                if (r < 0)
                        return r;
        }

        if (arg_start_exec_queue >= 0) {
                r = varlink_call_and_log(link, arg_start_exec_queue ? "io.systemd.Udev.StartExecQueue" : "io.systemd.Udev.StopExecQueue",
                                         /* parameters = */ NULL, /* reply = */ NULL);
                if (r < 0)
                        return r;
        }

        if (arg_reload) {
                r = varlink_call_and_log(link, "io.systemd.service.Reload", /* parameters = */ NULL, /* reply = */ NULL);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(arg_env)) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetEnvironment", /* reply = */ NULL,
                                           SD_JSON_BUILD_PAIR_STRV("assignments", arg_env));
                if (r < 0)
                        return r;
        }

        if (arg_max_children >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetChildrenMax", /* reply = */ NULL,
                                           SD_JSON_BUILD_PAIR_UNSIGNED("number", arg_max_children));
                if (r < 0)
                        return r;
        }

        if (arg_ping) {
                r = varlink_call_and_log(link, "io.systemd.service.Ping", /* parameters = */ NULL, /* reply = */ NULL);
                if (r < 0)
                        return r;
        }

        if (arg_trace >= 0) {
                r = varlink_callbo_and_log(link, "io.systemd.Udev.SetTrace", /* reply = */ NULL,
                                           SD_JSON_BUILD_PAIR_BOOLEAN("enable", arg_trace));
                if (r < 0)
                        return r;
        }

        return 0;
}

int control_main(int argc, char *argv[], void *userdata) {
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
