/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parse-util.h"
#include "process-util.h"
#include "syslog-util.h"
#include "time-util.h"
#include "udevadm.h"
#include "udev-ctrl.h"
#include "util.h"
#include "virt.h"

static int help(void) {
        printf("%s control OPTION\n\n"
               "Control the udev daemon.\n\n"
               "  -h --help                Show this help\n"
               "  -V --version             Show package version\n"
               "  -e --exit                Instruct the daemon to cleanup and exit\n"
               "  -l --log-priority=LEVEL  Set the udev log level for the daemon\n"
               "  -s --stop-exec-queue     Do not execute events, queue only\n"
               "  -S --start-exec-queue    Execute events, flush queue\n"
               "  -R --reload              Reload rules and databases\n"
               "  -p --property=KEY=VALUE  Set a global property for all events\n"
               "  -m --children-max=N      Maximum number of children\n"
               "  -t --timeout=SECONDS     Maximum time to block for a reply\n"
               , program_invocation_short_name);

        return 0;
}

int control_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_ctrl_unrefp) struct udev_ctrl *uctrl = NULL;
        int timeout = 60;
        int c, r;

        static const struct option options[] = {
                { "exit",             no_argument,       NULL, 'e' },
                { "log-priority",     required_argument, NULL, 'l' },
                { "stop-exec-queue",  no_argument,       NULL, 's' },
                { "start-exec-queue", no_argument,       NULL, 'S' },
                { "reload",           no_argument,       NULL, 'R' },
                { "reload-rules",     no_argument,       NULL, 'R' }, /* alias for -R */
                { "property",         required_argument, NULL, 'p' },
                { "env",              required_argument, NULL, 'p' }, /* alias for -p */
                { "children-max",     required_argument, NULL, 'm' },
                { "timeout",          required_argument, NULL, 't' },
                { "version",          no_argument,       NULL, 'V' },
                { "help",             no_argument,       NULL, 'h' },
                {}
        };

        r = must_be_root();
        if (r < 0)
                return r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        if (argc <= 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This command expects one or more options.");

        uctrl = udev_ctrl_new();
        if (!uctrl)
                return log_oom();

        while ((c = getopt_long(argc, argv, "el:sSRp:m:t:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'e':
                        r = udev_ctrl_send_exit(uctrl, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 'l':
                        r = log_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log priority '%s': %m", optarg);

                        r = udev_ctrl_send_set_log_level(uctrl, r, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 's':
                        r = udev_ctrl_send_stop_exec_queue(uctrl, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 'S':
                        r = udev_ctrl_send_start_exec_queue(uctrl, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 'R':
                        r = udev_ctrl_send_reload(uctrl, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 'p':
                        if (!strchr(optarg, '=')) {
                                log_error("expect <KEY>=<value> instead of '%s'", optarg);
                                return -EINVAL;
                        }
                        r = udev_ctrl_send_set_env(uctrl, optarg, timeout);
                        if (r < 0)
                                return r;
                        break;
                case 'm': {
                        unsigned i;

                        r = safe_atou(optarg, &i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse maximum number of events '%s': %m", optarg);

                        r = udev_ctrl_send_set_children_max(uctrl, i, timeout);
                        if (r < 0)
                                return r;
                        break;
                }
                case 't': {
                        usec_t s;

                        r = parse_sec(optarg, &s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s'.", optarg);

                        if (DIV_ROUND_UP(s, USEC_PER_SEC) > INT_MAX)
                                log_error("Timeout value is out of range, ignoring.");
                        else
                                timeout = s != USEC_INFINITY ? (int) DIV_ROUND_UP(s, USEC_PER_SEC) : INT_MAX;
                        break;
                }
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option.");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous argument: %s", argv[optind]);

        return 0;
}
