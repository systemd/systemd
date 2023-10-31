/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "creds-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "udevadm.h"
#include "udev-connection.h"
#include "udev-ctrl.h"
#include "udev-varlink.h"
#include "virt.h"

static char **arg_env = NULL;
static usec_t arg_timeout = 60 * USEC_PER_SEC;
static bool arg_ping = false;
static bool arg_reload = false;
static bool arg_exit = false;
static int arg_max_children = -1;
static int arg_log_level = -1;
static int arg_start_exec_queue = -1;
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
                arg_ping;
}

static int send_reload(UdevConnection *conn) {
        assert(conn);
        assert(conn->link || conn->uctrl);

        if (!conn->link)
                return udev_ctrl_send_reload(conn->uctrl);

        return udev_varlink_call(conn->link, "io.systemd.service.Reload", NULL, NULL);
}

static int send_set_log_level(UdevConnection *conn, int level) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(conn);
        assert(conn->link || conn->uctrl);

        if (!conn->link)
                return udev_ctrl_send_set_log_level(conn->uctrl, level);

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR("level", SD_JSON_BUILD_INTEGER(level)));
        if (r < 0)
                return log_error_errno(r, "Failed to build json object: %m");

        return udev_varlink_call(conn->link, "io.systemd.service.SetLogLevel", v, NULL);
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
               "  -t --timeout=SECONDS     Maximum time to block for a reply\n"
               "     --load-credentials    Load udev rules from credentials\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PING = 0x100,
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

static int send_control_commands(void) {
        _cleanup_(udev_connection_done) UdevConnection conn = {};
        int r;

        r = udev_connection_init(&conn, arg_timeout);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev connection: %m");

        if (arg_exit) {
                r = udev_ctrl_send_exit(conn.uctrl);
                if (r < 0)
                       return log_error_errno(r, "Failed to send exit request: %m");
                return 0;
        }

        if (arg_log_level >= 0) {
                r = send_set_log_level(&conn, arg_log_level);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set log level: %m");
        }

        if (arg_start_exec_queue == false) {
                r = udev_ctrl_send_stop_exec_queue(conn.uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to stop exec queue: %m");
        }

        if (arg_start_exec_queue == true) {
                r = udev_ctrl_send_start_exec_queue(conn.uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to start exec queue: %m");
        }

        if (arg_reload) {
                r = send_reload(&conn);
                if (r < 0)
                        return log_error_errno(r, "Failed to send reload request: %m");
        }

        STRV_FOREACH(env, arg_env) {
                r = udev_ctrl_send_set_env(conn.uctrl, *env);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to update environment: %m");
        }

        if (arg_max_children >= 0) {
                r = udev_ctrl_send_set_children_max(conn.uctrl, arg_max_children);
                if (r < 0)
                        return log_error_errno(r, "Failed to send request to set number of children: %m");
        }

        if (arg_ping) {
                r = udev_connection_send_ping(&conn);
                if (r < 0)
                        return log_error_errno(r, "Failed to send a ping message: %m");
        }

        r = udev_connection_wait(&conn);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for daemon to reply: %m");

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
