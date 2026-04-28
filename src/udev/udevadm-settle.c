/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-util.h"
#include "format-table.h"
#include "help-util.h"
#include "options.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-util.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "unit-def.h"
#include "virt.h"

static usec_t arg_timeout_usec = 120 * USEC_PER_SEC;
static const char *arg_exists = NULL;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-settle", &options);
        if (r < 0)
                return r;

        help_cmdline("settle [OPTIONS]");
        help_abstract("Wait for pending udev events.");
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

        OptionParser opts = { argc, argv, .namespace = "udevadm-settle" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_NAMESPACE("udevadm-settle"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('t', "timeout", "SEC", "Maximum time to wait for events"):
                        r = parse_sec(opts.arg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout value '%s': %m", opts.arg);
                        break;

                OPTION('E', "exit-if-exists", "FILE", "Stop waiting if file exists"):
                        if (!path_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path: %s", opts.arg);

                        arg_exists = opts.arg;
                        break;

                OPTION('s', "seq-start", "ARG", NULL): {} /* removed */
                OPTION('e', "seq-end", "ARG", NULL): {} /* removed */
                OPTION('q', "quiet", NULL, NULL): /* removed */
                        return log_info_errno(SYNTHETIC_ERRNO(EINVAL),
                                              "Option -%c no longer supported.",
                                              opts.opt->short_code);
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

                r = strv_extend_strv_consume(&a, TAKE_PTR(b), /* filter_duplicates= */ true);
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
                           LOG_ITEM("OFFENDING_UNITS=%s", t),
                           LOG_MESSAGE_ID(SD_MESSAGE_SYSTEMD_UDEV_SETTLE_DEPRECATED_STR));
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

int verb_settle_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
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
                r = udev_ping(MAX(5 * USEC_PER_SEC, arg_timeout_usec), /* ignore_connection_failure= */ true);
                if (r <= 0)
                        return r;
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
                return log_error_errno(r, "Timed out while waiting for udev queue to empty.");
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
