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

#include "process-util.h"
#include "time-util.h"
#include "udev.h"
#include "udevadm-util.h"

static void print_help(void) {
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
}

static int adm_control(struct udev *udev, int argc, char *argv[]) {
        _cleanup_(udev_ctrl_unrefp) struct udev_ctrl *uctrl = NULL;
        int timeout = 60;
        int rc = 1, c;

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

        if (must_be_root() < 0)
                return 1;

        uctrl = udev_ctrl_new(udev);
        if (uctrl == NULL)
                return 2;

        while ((c = getopt_long(argc, argv, "el:sSRp:m:t:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'e':
                        if (udev_ctrl_send_exit(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'l': {
                        int i;

                        i = util_log_priority(optarg);
                        if (i < 0) {
                                log_error("invalid number '%s'", optarg);
                                return rc;
                        }
                        if (udev_ctrl_send_set_log_level(uctrl, util_log_priority(optarg), timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                }
                case 's':
                        if (udev_ctrl_send_stop_exec_queue(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'S':
                        if (udev_ctrl_send_start_exec_queue(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'R':
                        if (udev_ctrl_send_reload(uctrl, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'p':
                        if (strchr(optarg, '=') == NULL) {
                                log_error("expect <KEY>=<value> instead of '%s'", optarg);
                                return rc;
                        }
                        if (udev_ctrl_send_set_env(uctrl, optarg, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                case 'm': {
                        char *endp;
                        int i;

                        i = strtoul(optarg, &endp, 0);
                        if (endp[0] != '\0' || i < 1) {
                                log_error("invalid number '%s'", optarg);
                                return rc;
                        }
                        if (udev_ctrl_send_set_children_max(uctrl, i, timeout) < 0)
                                rc = 2;
                        else
                                rc = 0;
                        break;
                }
                case 't': {
                        int r, seconds;
                        usec_t s;

                        r = parse_sec(optarg, &s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s'.", optarg);

                        if (DIV_ROUND_UP(s, USEC_PER_SEC) > INT_MAX)
                                log_error("Timeout value is out of range.");
                        else {
                                seconds = s != USEC_INFINITY ? (int) DIV_ROUND_UP(s, USEC_PER_SEC) : INT_MAX;
                                timeout = seconds;
                                rc = 0;
                        }
                        break;
                }
                case 'V':
                        print_version();
                        rc = 0;
                        break;
                case 'h':
                        print_help();
                        rc = 0;
                        break;
                }

        if (optind < argc)
                log_error("Extraneous argument: %s", argv[optind]);
        else if (optind == 1)
                log_error("Option missing");
        return rc;
}

const struct udevadm_cmd udevadm_control = {
        .name = "control",
        .cmd = adm_control,
        .help = "Control the udev daemon",
};
