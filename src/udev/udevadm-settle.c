/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <getopt.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "bus-util.h"
#include "path-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-ctrl.h"
#include "udev-util.h"
#include "udevadm.h"
#include "unit-def.h"
#include "virt.h"

static usec_t arg_timeout_usec = 120 * USEC_PER_SEC;
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
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", optarg);
                        break;
                case 'E':
                        if (!path_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path: %s", optarg);

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
                        assert_not_reached();
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
                           LOG_MESSAGE("systemd-udev-settle.service is deprecated. Please fix %s not to pull it in.", t),
                           "OFFENDING_UNITS=%s", t,
                           "MESSAGE_ID=" SD_MESSAGE_SYSTEMD_UDEV_SETTLE_DEPRECATED_STR);
        }

        return 0;
}

static bool check(void) {
        int r;

        if (arg_exists) {
                if (access(arg_exists, F_OK) >= 0)
                        return true;

                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to check the existence of \"%s\", ignoring: %m", arg_exists);
        }

        /* exit if queue is empty */
        r = udev_queue_is_empty();
        if (r < 0)
                log_warning_errno(r, "Failed to check if udev queue is empty, ignoring: %m");

        return r > 0;
}

static int on_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        assert(s);

        if (check())
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

int settle_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        (void) emit_deprecation_warning();

        if (getuid() == 0) {
                _cleanup_(udev_ctrl_unrefp) UdevCtrl *uctrl = NULL;

                /* guarantee that the udev daemon isn't pre-processing */

                r = udev_ctrl_new(&uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to create control socket for udev daemon: %m");

                r = udev_ctrl_send_ping(uctrl);
                if (r < 0) {
                        log_debug_errno(r, "Failed to connect to udev daemon, ignoring: %m");
                        return 0;
                }

                r = udev_ctrl_wait(uctrl, MAX(5 * USEC_PER_SEC, arg_timeout_usec));
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for daemon to reply: %m");
        } else {
                /* For non-privileged users, at least check if udevd is running. */
                if (access("/run/udev/control", F_OK) < 0)
                        return log_error_errno(errno,
                                               errno == ENOENT ? "systemd-udevd is not running." :
                                                                 "Failed to check if /run/udev/control exists: %m");
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default sd-event object: %m");

        r = sd_event_add_inotify(event, NULL, "/run/udev" , IN_DELETE, on_inotify, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add inotify watch for /run/udev: %m");

        if (arg_timeout_usec != USEC_INFINITY) {
                r = sd_event_add_time_relative(event, NULL, CLOCK_BOOTTIME, arg_timeout_usec, 0,
                                               NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0)
                        return log_error_errno(r, "Failed to add timer event source: %m");
        }

        /* Check before entering the event loop, as the udev queue may be already empty. */
        if (check())
                return 0;

        r = sd_event_loop(event);
        if (r == -ETIMEDOUT)
                return log_error_errno(r, "Timed out for waiting the udev queue being empty.");
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
