/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>

#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "set.h"
#include "signal-util.h"
#include "static-destruct.h"
#include "string-util.h"
#include "time-util.h"
#include "udevadm.h"
#include "virt.h"

static bool arg_show_property = false;
static bool arg_print_kernel = false;
static bool arg_print_udev = false;
static Set *arg_tag_filter = NULL;
static Hashmap *arg_subsystem_filter = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_tag_filter, set_freep);
STATIC_DESTRUCTOR_REGISTER(arg_subsystem_filter, hashmap_freep);

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        sd_device_action_t action = _SD_DEVICE_ACTION_INVALID;
        const char *devpath = NULL, *subsystem = NULL;
        MonitorNetlinkGroup group = PTR_TO_INT(userdata);
        struct timespec ts;

        assert(device);
        assert(IN_SET(group, MONITOR_GROUP_UDEV, MONITOR_GROUP_KERNEL));

        (void) sd_device_get_action(device, &action);
        (void) sd_device_get_devpath(device, &devpath);
        (void) sd_device_get_subsystem(device, &subsystem);

        assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

        printf("%-6s[%"PRI_TIME".%06"PRI_NSEC"] %-8s %s (%s)\n",
               group == MONITOR_GROUP_UDEV ? "UDEV" : "KERNEL",
               ts.tv_sec, (nsec_t)ts.tv_nsec/1000,
               strna(device_action_to_string(action)),
               devpath, subsystem);

        if (arg_show_property) {
                FOREACH_DEVICE_PROPERTY(device, key, value)
                        printf("%s=%s\n", key, value);

                printf("\n");
        }

        return 0;
}

static int setup_monitor(MonitorNetlinkGroup sender, sd_event *event, sd_device_monitor **ret) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        const char *subsystem, *devtype, *tag;
        int r;

        r = device_monitor_new_full(&monitor, sender, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to create netlink socket: %m");

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event: %m");

        HASHMAP_FOREACH_KEY(devtype, subsystem, arg_subsystem_filter) {
                r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, devtype);
                if (r < 0)
                        return log_error_errno(r, "Failed to apply subsystem filter '%s%s%s': %m",
                                               subsystem, devtype ? "/" : "", strempty(devtype));
        }

        SET_FOREACH(tag, arg_tag_filter) {
                r = sd_device_monitor_filter_add_match_tag(monitor, tag);
                if (r < 0)
                        return log_error_errno(r, "Failed to apply tag filter '%s': %m", tag);
        }

        r = sd_device_monitor_start(monitor, device_monitor_handler, INT_TO_PTR(sender));
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        (void) sd_device_monitor_set_description(monitor, sender == MONITOR_GROUP_UDEV ? "udev" : "kernel");

        *ret = TAKE_PTR(monitor);
        return 0;
}

static int help(void) {
        printf("%s monitor [OPTIONS]\n\n"
               "Listen to kernel and udev events.\n\n"
               "  -h --help                                Show this help\n"
               "  -V --version                             Show package version\n"
               "  -p --property                            Print the event properties\n"
               "  -k --kernel                              Print kernel uevents\n"
               "  -u --udev                                Print udev events\n"
               "  -s --subsystem-match=SUBSYSTEM[/DEVTYPE] Filter events by subsystem\n"
               "  -t --tag-match=TAG                       Filter events by tag\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "property",        no_argument,       NULL, 'p' },
                { "environment",     no_argument,       NULL, 'e' }, /* alias for -p */
                { "kernel",          no_argument,       NULL, 'k' },
                { "udev",            no_argument,       NULL, 'u' },
                { "subsystem-match", required_argument, NULL, 's' },
                { "tag-match",       required_argument, NULL, 't' },
                { "version",         no_argument,       NULL, 'V' },
                { "help",            no_argument,       NULL, 'h' },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "pekus:t:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'p':
                case 'e':
                        arg_show_property = true;
                        break;
                case 'k':
                        arg_print_kernel = true;
                        break;
                case 'u':
                        arg_print_udev = true;
                        break;
                case 's': {
                        _cleanup_free_ char *subsystem = NULL, *devtype = NULL;
                        const char *slash;

                        slash = strchr(optarg, '/');
                        if (slash) {
                                devtype = strdup(slash + 1);
                                if (!devtype)
                                        return log_oom();

                                subsystem = strndup(optarg, slash - optarg);
                        } else
                                subsystem = strdup(optarg);

                        if (!subsystem)
                                return log_oom();

                        r = hashmap_ensure_put(&arg_subsystem_filter, &trivial_hash_ops_free_free, subsystem, devtype);
                        if (r < 0)
                                return log_oom();

                        TAKE_PTR(subsystem);
                        TAKE_PTR(devtype);
                        break;
                }
                case 't':
                        r = set_put_strdup(&arg_tag_filter, optarg);
                        if (r < 0)
                                return log_oom();
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

        if (!arg_print_kernel && !arg_print_udev) {
                arg_print_kernel = true;
                arg_print_udev = true;
        }

        return 1;
}

int monitor_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *kernel_monitor = NULL, *udev_monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        /* Callers are expecting to see events as they happen: Line buffering */
        setlinebuf(stdout);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize event: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handling: %m");

        printf("monitor will print the received events for:\n");
        if (arg_print_udev) {
                r = setup_monitor(MONITOR_GROUP_UDEV, event, &udev_monitor);
                if (r < 0)
                        return r;

                printf("UDEV - the event which udev sends out after rule processing\n");
        }

        if (arg_print_kernel) {
                r = setup_monitor(MONITOR_GROUP_KERNEL, event, &kernel_monitor);
                if (r < 0)
                        return r;

                printf("KERNEL - the kernel uevent\n");
        }
        printf("\n");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}
