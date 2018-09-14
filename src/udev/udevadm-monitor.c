/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <time.h>

#include "libudev.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "device-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "libudev-private.h"
#include "set.h"
#include "string-util.h"
#include "udevadm.h"

static bool udev_exit = false;
static bool arg_show_property = false;
static bool arg_print_kernel = false;
static bool arg_print_udev = false;
static Set *arg_tag_filter = NULL;
static Hashmap *arg_subsystem_filter = NULL;

static void sig_handler(int signum) {
        if (IN_SET(signum, SIGINT, SIGTERM))
                udev_exit = true;
}

static int receive_and_print_device(struct udev_monitor *monitor, const char *source) {
        const char *action = NULL, *devpath = NULL, *subsystem = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        struct timespec ts;
        int r;

        r = udev_monitor_receive_sd_device(monitor, &device);
        if (r < 0)
                return log_debug_errno(r, "Failed to receive device from %s, ignoring: %m", source);

        (void) sd_device_get_property_value(device, "ACTION", &action);
        (void) sd_device_get_devpath(device, &devpath);
        (void) sd_device_get_subsystem(device, &subsystem);

        assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

        printf("%-6s[%"PRI_TIME".%06"PRI_NSEC"] %-8s %s (%s)\n",
               source,
               ts.tv_sec, (nsec_t)ts.tv_nsec/1000,
               action, devpath, subsystem);

        if (arg_show_property) {
                const char *key, *value;

                FOREACH_DEVICE_PROPERTY(device, key, value)
                        printf("%s=%s\n", key, value);

                printf("\n");
        }

        return 0;
}

static int setup_monitor(const char *sender, int fd_epoll, struct udev_monitor **ret) {
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *monitor = NULL;
        const char *subsystem, *devtype, *tag;
        struct epoll_event ep = {};
        Iterator i;
        int fd, r;

        monitor = udev_monitor_new_from_netlink(NULL, sender);
        if (!monitor)
                return log_error_errno(errno, "Failed to create netlink socket: %m");

        r = udev_monitor_set_receive_buffer_size(monitor, 128*1024*1024);
        if (r < 0)
                return log_error_errno(r, "Failed to set receive buffer size: %m");

        fd = udev_monitor_get_fd(monitor);
        if (fd < 0)
                return log_error_errno(r, "Failed to get socket fd for monitoring: %m");

        HASHMAP_FOREACH_KEY(devtype, subsystem, arg_subsystem_filter, i) {
                r = udev_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, devtype);
                if (r < 0)
                        return log_error_errno(r, "Failed to apply subsystem filter '%s%s%s': %m",
                                               subsystem, devtype ? "/" : "", strempty(devtype));
        }

        SET_FOREACH(tag, arg_tag_filter, i) {
                r = udev_monitor_filter_add_match_tag(monitor, tag);
                if (r < 0)
                        return log_error_errno(r, "Failed to apply tag filter '%s': %m", tag);
        }

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to subscribe %s events: %m", sender);

        ep = (struct epoll_event) {
                .events = EPOLLIN,
                .data.fd = fd,
        };

        if (epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd, &ep) < 0)
                return log_error_errno(errno, "Failed to add fd to epoll: %m");

        *ret = TAKE_PTR(monitor);
        return fd;
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
               "  -t --tag-match=TAG                       Filter events by tag\n"
               , program_invocation_short_name);

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
                                devtype = strdup(devtype + 1);
                                if (!devtype)
                                        return -ENOMEM;

                                subsystem = strndup(optarg, devtype - optarg);
                        } else
                                subsystem = strdup(optarg);

                        if (!subsystem)
                                return -ENOMEM;

                        r = hashmap_ensure_allocated(&arg_subsystem_filter, NULL);
                        if (r < 0)
                                return r;

                        r = hashmap_put(arg_subsystem_filter, subsystem, devtype);
                        if (r < 0)
                                return r;

                        subsystem = devtype = NULL;
                        break;
                }
                case 't': {
                        _cleanup_free_ char *tag = NULL;

                        r = set_ensure_allocated(&arg_tag_filter, &string_hash_ops);
                        if (r < 0)
                                return r;

                        tag = strdup(optarg);
                        if (!tag)
                                return -ENOMEM;

                        r = set_put(arg_tag_filter, tag);
                        if (r < 0)
                                return r;

                        tag = NULL;
                        break;
                }
                case 'V':
                        return version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option.");
                }

        if (!arg_print_kernel && !arg_print_udev) {
                arg_print_kernel = true;
                arg_print_udev = true;
        }

        return 1;
}

int monitor_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *kernel_monitor = NULL, *udev_monitor = NULL;
        int fd_kernel = -1, fd_udev = -1;
        _cleanup_close_ int fd_ep = -1;
        struct sigaction act;
        sigset_t mask;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finalize;

        /* set signal handlers */
        act = (struct sigaction) {
                .sa_handler = sig_handler,
                .sa_flags = SA_RESTART,
        };
        assert_se(sigaction(SIGINT, &act, NULL) == 0);
        assert_se(sigaction(SIGTERM, &act, NULL) == 0);
        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGINT) == 0);
        assert_se(sigaddset(&mask, SIGTERM) == 0);
        assert_se(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);

        /* Callers are expecting to see events as they happen: Line buffering */
        setlinebuf(stdout);

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                r = log_error_errno(errno, "Failed to create epoll fd: %m");
                goto finalize;
        }

        printf("monitor will print the received events for:\n");
        if (arg_print_udev) {
                fd_udev = setup_monitor("udev", fd_ep, &udev_monitor);
                if (fd_udev < 0) {
                        r = fd_udev;
                        goto finalize;
                }

                printf("UDEV - the event which udev sends out after rule processing\n");
        }

        if (arg_print_kernel) {
                fd_kernel = setup_monitor("kernel", fd_ep, &kernel_monitor);
                if (fd_kernel < 0) {
                        r = fd_kernel;
                        goto finalize;
                }

                printf("KERNEL - the kernel uevent\n");
        }
        printf("\n");

        while (!udev_exit) {
                struct epoll_event ev[4];
                int fdcount, i;

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                if (fdcount < 0) {
                        if (errno != EINTR)
                                log_debug_errno(errno, "Failed to receive uevent message, ignoring: %m");
                        continue;
                }

                for (i = 0; i < fdcount; i++)
                        if (ev[i].data.fd == fd_kernel && ev[i].events & EPOLLIN)
                                (void) receive_and_print_device(kernel_monitor, "KERNEL");
                        else if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN)
                                (void) receive_and_print_device(udev_monitor, "UDEV");
        }

        r = 0;

finalize:
        hashmap_free_free_free(arg_subsystem_filter);
        set_free_free(arg_tag_filter);

        return r;
}
