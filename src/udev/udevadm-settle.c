/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "bus-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-ctrl.h"
#include "udev-util.h"
#include "udevadm.h"
#include "unit-def.h"
#include "util.h"
#include "virt.h"

static usec_t arg_timeout = 120 * USEC_PER_SEC;
static const char *arg_exists = NULL;

static int help(void) {
        printf("%s settle [OPTIONS]\n\n"
               "Wait for pending udev events.\n\n"
               "  -h --help                 Show this help\n"
               "  -V --version              Show package version\n"
               "  -t --timeout=SEC          Maximum time to wait for events\n"
               "  -E --exit-if-exists=FILE  Stop waiting if file exists\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "timeout",        required_argument, NULL, 't' },
                { "exit-if-exists", required_argument, NULL, 'E' },
                { "version",        no_argument,       NULL, 'V' },
                { "help",           no_argument,       NULL, 'h' },
                { "seq-start",      required_argument, NULL, 's' }, /* removed */
                { "seq-end",        required_argument, NULL, 'e' }, /* removed */
                { "quiet",          no_argument,       NULL, 'q' }, /* removed */
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "t:E:Vhs:e:q", options, NULL)) >= 0) {
                switch (c) {
                case 't':
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                        break;
                case 'E':
                        arg_exists = optarg;
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case 's':
                case 'e':
                case 'q':
                        return log_info_errno(SYNTHETIC_ERRNO(EINVAL),
                                              "Option -%c no longer supported.",
                                              c);
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option.");
                }
        }

        return 1;
}

static int emit_deprecation_warning(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        r = sd_pid_get_unit(0, &unit);
        if (r < 0) {
                log_debug_errno(r, "Failed to determine unit we run in, ignoring: %m");
                return 0;
        }

        if (!streq(unit, "systemd-udev-settle.service"))
                return 0;

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                log_debug_errno(r, "Failed to open connection to systemd, skipping dependency queries: %m");
        else {
                _cleanup_strv_free_ char **b = NULL;
                _cleanup_free_ char *unit_path = NULL;

                unit_path = unit_dbus_path_from_name("systemd-udev-settle.service");
                if (!unit_path)
                        return -ENOMEM;

                (void) sd_bus_get_property_strv(
                                bus,
                                "org.freedesktop.systemd1",
                                unit_path,
                                "org.freedesktop.systemd1.Unit",
                                "WantedBy",
                                NULL,
                                &a);

                (void) sd_bus_get_property_strv(
                                bus,
                                "org.freedesktop.systemd1",
                                unit_path,
                                "org.freedesktop.systemd1.Unit",
                                "RequiredBy",
                                NULL,
                                &b);

                r = strv_extend_strv(&a, b, true);
                if (r < 0)
                        return r;
        }

        if (strv_isempty(a))
                /* Print a simple message if we cannot determine the dependencies */
                log_notice("systemd-udev-settle.service is deprecated.");
        else {
                /* Print a longer, structured message if we can acquire the dependencies (this should be the
                 * common case). This is hooked up with a catalog entry and everything. */
                _cleanup_free_ char *t = NULL;

                t = strv_join(a, ", ");
                if (!t)
                        return -ENOMEM;

                log_struct(LOG_NOTICE,
                           "MESSAGE=systemd-udev-settle.service is deprecated. Please fix %s not to pull it in.", t,
                           "OFFENDING_UNITS=%s", t,
                           "MESSAGE_ID=" SD_MESSAGE_SYSTEMD_UDEV_SETTLE_DEPRECATED_STR);
        }

        return 0;
}

int settle_main(int argc, char *argv[], void *userdata) {
        _cleanup_close_ int fd = -1;
        usec_t deadline;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        deadline = now(CLOCK_MONOTONIC) + arg_timeout;

        /* guarantee that the udev daemon isn't pre-processing */
        if (getuid() == 0) {
                _cleanup_(udev_ctrl_unrefp) struct udev_ctrl *uctrl = NULL;

                if (udev_ctrl_new(&uctrl) >= 0) {
                        r = udev_ctrl_send_ping(uctrl);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to connect to udev daemon: %m");
                                return 0;
                        }

                        r = udev_ctrl_wait(uctrl, MAX(5 * USEC_PER_SEC, arg_timeout));
                        if (r < 0)
                                return log_error_errno(r, "Failed to wait for daemon to reply: %m");
                }
        }

        fd = udev_queue_init();
        if (fd < 0) {
                log_debug_errno(fd, "Queue is empty, nothing to watch: %m");
                return 0;
        }

        (void) emit_deprecation_warning();

        for (;;) {
                if (arg_exists && access(arg_exists, F_OK) >= 0)
                        return 0;

                /* exit if queue is empty */
                r = udev_queue_is_empty();
                if (r < 0)
                        return log_error_errno(r, "Failed to check queue is empty: %m");
                if (r > 0)
                        return 0;

                if (now(CLOCK_MONOTONIC) >= deadline)
                        return -ETIMEDOUT;

                /* wake up when queue becomes empty */
                r = fd_wait_for_event(fd, POLLIN, MSEC_PER_SEC);
                if (r < 0)
                        return r;
                if (r & POLLIN) {
                        r = flush_fd(fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to flush queue: %m");
                }
        }
}
