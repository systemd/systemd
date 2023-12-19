/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "chase.h"
#include "device-monitor-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "inotify-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "static-destruct.h"
#include "string-table.h"
#include "strv.h"
#include "udev-util.h"
#include "udevadm.h"

typedef enum WaitUntil {
        WAIT_UNTIL_INITIALIZED,
        WAIT_UNTIL_ADDED,
        WAIT_UNTIL_REMOVED,
        WAIT_UNTIL_CHANGED,
        _WAIT_UNTIL_MAX,
        _WAIT_UNTIL_INVALID = -EINVAL,
} WaitUntil;

static WaitUntil arg_wait_until = WAIT_UNTIL_INITIALIZED;
static usec_t arg_timeout_usec = USEC_INFINITY;
static bool arg_settle = false;
static char **arg_devices = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_devices, strv_freep);

static const char * const wait_until_table[_WAIT_UNTIL_MAX] = {
        [WAIT_UNTIL_INITIALIZED] = "initialized",
        [WAIT_UNTIL_ADDED]       = "added",
        [WAIT_UNTIL_REMOVED]     = "removed",
        [WAIT_UNTIL_CHANGED]     = "changed",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(wait_until, WaitUntil);

static int check_device(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(path);

        if (arg_wait_until == WAIT_UNTIL_REMOVED || arg_wait_until == WAIT_UNTIL_CHANGED) {
                r = laccess(path, F_OK);
                if (r == -ENOENT)
                        return true;
                if (r < 0)
                        return r;
                return false;
        }

        r = sd_device_new_from_path(&dev, path);
        if (r == -ENODEV)
                return false;
        if (r < 0)
                return r;

        if (arg_wait_until == WAIT_UNTIL_INITIALIZED)
                return sd_device_get_is_initialized(dev);

        return true;
}

static bool check(void) {
        int r;

        if (arg_settle) {
                r = udev_queue_is_empty();
                if (r == 0)
                        return false;
                if (r < 0)
                        log_warning_errno(r, "Failed to check if udev queue is empty, assuming empty: %m");
        }

        STRV_FOREACH(p, arg_devices) {
                r = check_device(*p);
                if (r <= 0) {
                        if (r < 0)
                                log_warning_errno(r, "Failed to check if device \"%s\" is %s, assuming not %s: %m",
                                                  *p,
                                                  wait_until_to_string(arg_wait_until),
                                                  wait_until_to_string(arg_wait_until));
                        return false;
                }
        }

        return true;
}

static int check_and_exit(sd_event *event) {
        int r;

        assert(event);

        if (check() || arg_wait_until == WAIT_UNTIL_CHANGED) {
                r = sd_event_exit(event, 0);
                if (r < 0)
                        return r;

                return 1;
        }

        return 0;
}

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        const char *name;
        int r;

        assert(monitor);
        assert(device);

        if (arg_wait_until == WAIT_UNTIL_CHANGED &&
            !device_for_action(device, SD_DEVICE_REMOVE) && !device_for_action(device, SD_DEVICE_CHANGE))
                /* Allow a REMOVE event to trigger WAIT_UNTIL_CHANGED also. */
                return 0;
        else if (device_for_action(device, SD_DEVICE_REMOVE) != (arg_wait_until == WAIT_UNTIL_REMOVED))
                return 0;

        if (arg_wait_until == WAIT_UNTIL_REMOVED)
                /* On removed event, the received device may not contain enough information.
                 * Let's unconditionally check all requested devices are removed. */
                return check_and_exit(sd_device_monitor_get_event(monitor));

        /* For other events, at first check if the received device matches with the requested devices,
         * to avoid calling check() so many times within a short time. */

        r = sd_device_get_sysname(device, &name);
        if (r < 0) {
                log_device_warning_errno(device, r, "Failed to get sysname of received device, ignoring: %m");
                return 0;
        }

        STRV_FOREACH(p, arg_devices) {
                const char *s;

                if (!path_startswith(*p, "/sys"))
                        continue;

                r = path_find_last_component(*p, false, NULL, &s);
                if (r < 0) {
                        log_warning_errno(r, "Failed to extract filename from \"%s\", ignoring: %m", *p);
                        continue;
                }
                if (r == 0)
                        continue;

                if (strneq(s, name, r))
                        return check_and_exit(sd_device_monitor_get_event(monitor));
        }

        r = sd_device_get_devname(device, &name);
        if (r < 0) {
                if (r != -ENOENT)
                        log_device_warning_errno(device, r, "Failed to get devname of received device, ignoring: %m");
                return 0;
        }

        if (path_strv_contains(arg_devices, name))
                return check_and_exit(sd_device_monitor_get_event(monitor));

        FOREACH_DEVICE_DEVLINK(device, link)
                if (path_strv_contains(arg_devices, link))
                        return check_and_exit(sd_device_monitor_get_event(monitor));

        return 0;
}

static int setup_monitor(sd_event *event, MonitorNetlinkGroup group, const char *description, sd_device_monitor **ret) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        int r;

        assert(event);
        assert(ret);

        r = device_monitor_new_full(&monitor, group, /* fd = */ -1);
        if (r < 0)
                return r;

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return r;

        r = sd_device_monitor_set_description(monitor, description);
        if (r < 0)
                return r;

        r = sd_device_monitor_start(monitor, device_monitor_handler, NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(monitor);
        return 0;
}

static int on_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        return check_and_exit(sd_event_source_get_event(s));
}

static int setup_inotify(sd_event *event) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(event);

        if (!arg_settle)
                return 0;

        r = sd_event_add_inotify(event, &s, "/run/udev" , IN_CREATE | IN_DELETE, on_inotify, NULL);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "inotify-event-source");
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

static int setup_timer(sd_event *event) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(event);

        if (arg_timeout_usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time_relative(event, &s, CLOCK_BOOTTIME, arg_timeout_usec, 0,
                                       NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "timeout-event-source");
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

static int reset_timer(sd_event *e, sd_event_source **s);

static int on_periodic_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        static unsigned counter = 0;
        sd_event *e;
        int r;

        assert(s);

        e = sd_event_source_get_event(s);

        /* Even if all devices exists, we try to wait for uevents to be emitted from kernel. */
        if (check())
                counter++;
        else
                counter = 0;

        if (counter >= 2) {
                log_debug("All requested devices popped up without receiving kernel uevents.");
                return sd_event_exit(e, 0);
        }

        r = reset_timer(e, &s);
        if (r < 0)
                log_warning_errno(r, "Failed to reset periodic timer event source, ignoring: %m");

        return 0;
}

static int reset_timer(sd_event *e, sd_event_source **s) {
        return event_reset_time_relative(e, s, CLOCK_BOOTTIME, 250 * USEC_PER_MSEC, 0,
                                         on_periodic_timer, NULL, 0, "periodic-timer-event-source", false);
}

static int setup_periodic_timer(sd_event *event) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(event);

        r = reset_timer(event, &s);
        if (r < 0)
                return r;

        /* Set the lower priority than device monitor, to make uevents always dispatched first. */
        r = sd_event_source_set_priority(s, SD_EVENT_PRIORITY_NORMAL + 1);
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

static int help(void) {
        printf("%s wait [OPTIONS] DEVICE [DEVICE…]\n\n"
               "Wait for devices or device symlinks being created.\n\n"
               "  -h --help             Print this message\n"
               "  -V --version          Print version of the program\n"
               "  -t --timeout=SEC      Maximum time to wait for the device\n"
               "     --initialized=BOOL Wait for devices being initialized by systemd-udevd\n"
               "     --removed          Wait for devices being removed\n"
               "     --changed          Wait for devices being changed\n"
               "     --settle           Also wait for all queued events being processed\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_INITIALIZED = 0x100,
                ARG_REMOVED,
                ARG_CHANGED,
                ARG_SETTLE,
        };

        static const struct option options[] = {
                { "timeout",     required_argument, NULL, 't'             },
                { "initialized", required_argument, NULL, ARG_INITIALIZED },
                { "removed",     no_argument,       NULL, ARG_REMOVED     },
                { "changed",     no_argument,       NULL, ARG_CHANGED     },
                { "settle",      no_argument,       NULL, ARG_SETTLE      },
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, 'V'             },
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "t:hV", options, NULL)) >= 0)
                switch (c) {
                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse -t/--timeout= parameter: %s", optarg);
                        break;

                case ARG_INITIALIZED:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --initialized= parameter: %s", optarg);
                        arg_wait_until = r ? WAIT_UNTIL_INITIALIZED : WAIT_UNTIL_ADDED;
                        break;

                case ARG_REMOVED:
                        arg_wait_until = WAIT_UNTIL_REMOVED;
                        break;

                case ARG_CHANGED:
                        arg_wait_until = WAIT_UNTIL_CHANGED;
                        break;

                case ARG_SETTLE:
                        arg_settle = true;
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

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too few arguments, expected at least one device path or device symlink.");

        arg_devices = strv_copy(argv + optind);
        if (!arg_devices)
                return log_oom();

        return 1; /* work to do */
}

int wait_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *udev_monitor = NULL, *kernel_monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        STRV_FOREACH(p, arg_devices) {
                path_simplify(*p);

                if (!path_is_safe(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Device path cannot contain \"..\".");

                if (!is_device_path(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Specified path \"%s\" does not start with \"/dev/\" or \"/sys/\".", *p);
        }

        /* Check before configuring event sources, as devices may be already initialized. */
        if (check())
                return 0;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize sd-event: %m");

        r = setup_timer(event);
        if (r < 0)
                return log_error_errno(r, "Failed to set up timeout: %m");

        r = setup_inotify(event);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify: %m");

        r = setup_monitor(event, MONITOR_GROUP_UDEV, "udev-uevent-monitor-event-source", &udev_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to set up udev uevent monitor: %m");

        if (arg_wait_until == WAIT_UNTIL_ADDED) {
                /* If --initialized=no is specified, it is not necessary to wait uevents for the specified
                 * devices to be processed by udevd. Hence, let's listen on the kernel's uevent stream. Then,
                 * we may be able to finish this program earlier when udevd is very busy.
                 * Note, we still need to also setup udev monitor, as this may be invoked with a devlink
                 * (e.g. /dev/disk/by-id/foo). In that case, the devlink may not exist when we received a
                 * uevent from kernel, as the udevd may not finish to process the uevent yet. Hence, we need
                 * to wait until the event is processed by udevd. */
                r = setup_monitor(event, MONITOR_GROUP_KERNEL, "kernel-uevent-monitor-event-source", &kernel_monitor);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up kernel uevent monitor: %m");

                /* This is a workaround for issues #24360 and #24450.
                 * For some reasons, the kernel sometimes does not emit uevents for loop block device on
                 * attach. Hence, without the periodic timer, no event source for this program will be
                 * triggered, and this will be timed out.
                 * Theoretically, inotify watch may be better, but this program typically expected to run in
                 * a short time. Hence, let's use the simpler periodic timer event source here. */
                r = setup_periodic_timer(event);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up periodic timer: %m");
        }

        /* Check before entering the event loop, as devices may be initialized during setting up event sources. */
        if (check())
                return 0;

        r = sd_event_loop(event);
        if (r == -ETIMEDOUT)
                return log_error_errno(r, "Timed out for waiting devices being %s.",
                                       wait_until_to_string(arg_wait_until));
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
