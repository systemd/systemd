/*
 * Copyright (C) 2004-2010 Kay Sievers <kay@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "udev.h"
#include "udev-util.h"
#include "formats-util.h"

static bool udev_exit;

static void sig_handler(int signum) {
        if (signum == SIGINT || signum == SIGTERM)
                udev_exit = true;
}

static void print_device(struct udev_device *device, const char *source, int prop) {
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("%-6s[%"PRI_TIME".%06ld] %-8s %s (%s)\n",
               source,
               ts.tv_sec, ts.tv_nsec/1000,
               udev_device_get_action(device),
               udev_device_get_devpath(device),
               udev_device_get_subsystem(device));
        if (prop) {
                struct udev_list_entry *list_entry;

                udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device))
                        printf("%s=%s\n",
                               udev_list_entry_get_name(list_entry),
                               udev_list_entry_get_value(list_entry));
                printf("\n");
        }
}

static void help(void) {
        printf("%s monitor [--property] [--kernel] [--udev] [--help]\n\n"
               "Listen to kernel and udev events.\n\n"
               "  -h --help                                Show this help\n"
               "     --version                             Show package version\n"
               "  -p --property                            Print the event properties\n"
               "  -k --kernel                              Print kernel uevents\n"
               "  -u --udev                                Print udev events\n"
               "  -s --subsystem-match=SUBSYSTEM[/DEVTYPE] Filter events by subsystem\n"
               "  -t --tag-match=TAG                       Filter events by tag\n"
               , program_invocation_short_name);
}

static int adm_monitor(struct udev *udev, int argc, char *argv[]) {
        struct sigaction act = {};
        sigset_t mask;
        bool prop = false;
        bool print_kernel = false;
        bool print_udev = false;
        _cleanup_udev_list_cleanup_ struct udev_list subsystem_match_list;
        _cleanup_udev_list_cleanup_ struct udev_list tag_match_list;
        _cleanup_udev_monitor_unref_ struct udev_monitor *udev_monitor = NULL;
        _cleanup_udev_monitor_unref_ struct udev_monitor *kernel_monitor = NULL;
        _cleanup_close_ int fd_ep = -1;
        int fd_kernel = -1, fd_udev = -1;
        struct epoll_event ep_kernel, ep_udev;
        int c;

        static const struct option options[] = {
                { "property",        no_argument,       NULL, 'p' },
                { "environment",     no_argument,       NULL, 'e' }, /* alias for -p */
                { "kernel",          no_argument,       NULL, 'k' },
                { "udev",            no_argument,       NULL, 'u' },
                { "subsystem-match", required_argument, NULL, 's' },
                { "tag-match",       required_argument, NULL, 't' },
                { "help",            no_argument,       NULL, 'h' },
                {}
        };

        udev_list_init(udev, &subsystem_match_list, true);
        udev_list_init(udev, &tag_match_list, true);

        while((c = getopt_long(argc, argv, "pekus:t:h", options, NULL)) >= 0)
                switch (c) {
                case 'p':
                case 'e':
                        prop = true;
                        break;
                case 'k':
                        print_kernel = true;
                        break;
                case 'u':
                        print_udev = true;
                        break;
                case 's':
                        {
                                char subsys[UTIL_NAME_SIZE];
                                char *devtype;

                                strscpy(subsys, sizeof(subsys), optarg);
                                devtype = strchr(subsys, '/');
                                if (devtype != NULL) {
                                        devtype[0] = '\0';
                                        devtype++;
                                }
                                udev_list_entry_add(&subsystem_match_list, subsys, devtype);
                                break;
                        }
                case 't':
                        udev_list_entry_add(&tag_match_list, optarg, NULL);
                        break;
                case 'h':
                        help();
                        return 0;
                default:
                        return 1;
                }

        if (!print_kernel && !print_udev) {
                print_kernel = true;
                print_udev = true;
        }

        /* set signal handlers */
        act.sa_handler = sig_handler;
        act.sa_flags = SA_RESTART;
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGTERM, &act, NULL);
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error_errno(errno, "error creating epoll fd: %m");
                return 1;
        }

        printf("monitor will print the received events for:\n");
        if (print_udev) {
                struct udev_list_entry *entry;

                udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
                if (udev_monitor == NULL) {
                        fprintf(stderr, "error: unable to create netlink socket\n");
                        return 1;
                }
                udev_monitor_set_receive_buffer_size(udev_monitor, 128*1024*1024);
                fd_udev = udev_monitor_get_fd(udev_monitor);

                udev_list_entry_foreach(entry, udev_list_get_entry(&subsystem_match_list)) {
                        const char *subsys = udev_list_entry_get_name(entry);
                        const char *devtype = udev_list_entry_get_value(entry);

                        if (udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, subsys, devtype) < 0)
                                fprintf(stderr, "error: unable to apply subsystem filter '%s'\n", subsys);
                }

                udev_list_entry_foreach(entry, udev_list_get_entry(&tag_match_list)) {
                        const char *tag = udev_list_entry_get_name(entry);

                        if (udev_monitor_filter_add_match_tag(udev_monitor, tag) < 0)
                                fprintf(stderr, "error: unable to apply tag filter '%s'\n", tag);
                }

                if (udev_monitor_enable_receiving(udev_monitor) < 0) {
                        fprintf(stderr, "error: unable to subscribe to udev events\n");
                        return 2;
                }

                memzero(&ep_udev, sizeof(struct epoll_event));
                ep_udev.events = EPOLLIN;
                ep_udev.data.fd = fd_udev;
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_udev, &ep_udev) < 0) {
                        log_error_errno(errno, "fail to add fd to epoll: %m");
                        return 2;
                }

                printf("UDEV - the event which udev sends out after rule processing\n");
        }

        if (print_kernel) {
                struct udev_list_entry *entry;

                kernel_monitor = udev_monitor_new_from_netlink(udev, "kernel");
                if (kernel_monitor == NULL) {
                        fprintf(stderr, "error: unable to create netlink socket\n");
                        return 3;
                }
                udev_monitor_set_receive_buffer_size(kernel_monitor, 128*1024*1024);
                fd_kernel = udev_monitor_get_fd(kernel_monitor);

                udev_list_entry_foreach(entry, udev_list_get_entry(&subsystem_match_list)) {
                        const char *subsys = udev_list_entry_get_name(entry);

                        if (udev_monitor_filter_add_match_subsystem_devtype(kernel_monitor, subsys, NULL) < 0)
                                fprintf(stderr, "error: unable to apply subsystem filter '%s'\n", subsys);
                }

                if (udev_monitor_enable_receiving(kernel_monitor) < 0) {
                        fprintf(stderr, "error: unable to subscribe to kernel events\n");
                        return 4;
                }

                memzero(&ep_kernel, sizeof(struct epoll_event));
                ep_kernel.events = EPOLLIN;
                ep_kernel.data.fd = fd_kernel;
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_kernel, &ep_kernel) < 0) {
                        log_error_errno(errno, "fail to add fd to epoll: %m");
                        return 5;
                }

                printf("KERNEL - the kernel uevent\n");
        }
        printf("\n");

        while (!udev_exit) {
                int fdcount;
                struct epoll_event ev[4];
                int i;

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                if (fdcount < 0) {
                        if (errno != EINTR)
                                fprintf(stderr, "error receiving uevent message: %m\n");
                        continue;
                }

                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_kernel && ev[i].events & EPOLLIN) {
                                struct udev_device *device;

                                device = udev_monitor_receive_device(kernel_monitor);
                                if (device == NULL)
                                        continue;
                                print_device(device, "KERNEL", prop);
                                udev_device_unref(device);
                        } else if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN) {
                                struct udev_device *device;

                                device = udev_monitor_receive_device(udev_monitor);
                                if (device == NULL)
                                        continue;
                                print_device(device, "UDEV", prop);
                                udev_device_unref(device);
                        }
                }
        }

        return 0;
}

const struct udevadm_cmd udevadm_monitor = {
        .name = "monitor",
        .cmd = adm_monitor,
        .help = "Listen to kernel and udev events",
};
