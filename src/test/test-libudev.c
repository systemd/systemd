/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/epoll.h>

#include "libudev.h"
#include "udev-util.h"
#include "util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void print_device(struct udev_device *device) {
        const char *str;
        dev_t devnum;
        int count;
        struct udev_list_entry *list_entry;

        printf("*** device: %p ***\n", device);
        str = udev_device_get_action(device);
        if (str != NULL)
                printf("action:    '%s'\n", str);

        str = udev_device_get_syspath(device);
        printf("syspath:   '%s'\n", str);

        str = udev_device_get_sysname(device);
        printf("sysname:   '%s'\n", str);

        str = udev_device_get_sysnum(device);
        if (str != NULL)
                printf("sysnum:    '%s'\n", str);

        str = udev_device_get_devpath(device);
        printf("devpath:   '%s'\n", str);

        str = udev_device_get_subsystem(device);
        if (str != NULL)
                printf("subsystem: '%s'\n", str);

        str = udev_device_get_devtype(device);
        if (str != NULL)
                printf("devtype:   '%s'\n", str);

        str = udev_device_get_driver(device);
        if (str != NULL)
                printf("driver:    '%s'\n", str);

        str = udev_device_get_devnode(device);
        if (str != NULL)
                printf("devname:   '%s'\n", str);

        devnum = udev_device_get_devnum(device);
        if (major(devnum) > 0)
                printf("devnum:    %u:%u\n", major(devnum), minor(devnum));

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
                printf("link:      '%s'\n", udev_list_entry_get_name(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i links\n", count);

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
                printf("property:  '%s=%s'\n",
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i properties\n", count);

        str = udev_device_get_property_value(device, "MAJOR");
        if (str != NULL)
                printf("MAJOR: '%s'\n", str);

        str = udev_device_get_sysattr_value(device, "dev");
        if (str != NULL)
                printf("attr{dev}: '%s'\n", str);

        printf("\n");
}

static int test_device(struct udev *udev, const char *syspath) {
        _cleanup_udev_device_unref_ struct udev_device *device;

        printf("looking at device: %s\n", syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (device == NULL) {
                printf("no device found\n");
                return -1;
        }
        print_device(device);

        return 0;
}

static int test_device_parents(struct udev *udev, const char *syspath) {
        _cleanup_udev_device_unref_ struct udev_device *device;
        struct udev_device *device_parent;

        printf("looking at device: %s\n", syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (device == NULL)
                return -1;

        printf("looking at parents\n");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);

        printf("looking at parents again\n");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);

        return 0;
}

static int test_device_devnum(struct udev *udev) {
        dev_t devnum = makedev(1, 3);
        struct udev_device *device;

        printf("looking up device: %u:%u\n", major(devnum), minor(devnum));
        device = udev_device_new_from_devnum(udev, 'c', devnum);
        if (device == NULL)
                return -1;
        print_device(device);
        udev_device_unref(device);
        return 0;
}

static int test_device_subsys_name(struct udev *udev) {
        struct udev_device *device;

        printf("looking up device: 'block':'sda'\n");
        device = udev_device_new_from_subsystem_sysname(udev, "block", "sda");
        if (device == NULL)
                return -1;
        print_device(device);
        udev_device_unref(device);

        printf("looking up device: 'subsystem':'pci'\n");
        device = udev_device_new_from_subsystem_sysname(udev, "subsystem", "pci");
        if (device == NULL)
                return -1;
        print_device(device);
        udev_device_unref(device);

        printf("looking up device: 'drivers':'scsi:sd'\n");
        device = udev_device_new_from_subsystem_sysname(udev, "drivers", "scsi:sd");
        if (device == NULL)
                return -1;
        print_device(device);
        udev_device_unref(device);

        printf("looking up device: 'module':'printk'\n");
        device = udev_device_new_from_subsystem_sysname(udev, "module", "printk");
        if (device == NULL)
                return -1;
        print_device(device);
        udev_device_unref(device);
        return 0;
}

static int test_enumerate_print_list(struct udev_enumerate *enumerate) {
        struct udev_list_entry *list_entry;
        int count = 0;

        udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(enumerate)) {
                struct udev_device *device;

                device = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
                                                      udev_list_entry_get_name(list_entry));
                if (device != NULL) {
                        printf("device: '%s' (%s)\n",
                               udev_device_get_syspath(device),
                               udev_device_get_subsystem(device));
                        udev_device_unref(device);
                        count++;
                }
        }
        printf("found %i devices\n\n", count);
        return count;
}

static int test_monitor(struct udev *udev) {
        struct udev_monitor *udev_monitor = NULL;
        int fd_ep;
        int fd_udev = -1;
        struct epoll_event ep_udev, ep_stdin;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                printf("error creating epoll fd: %m\n");
                goto out;
        }

        udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
        if (udev_monitor == NULL) {
                printf("no socket\n");
                goto out;
        }
        fd_udev = udev_monitor_get_fd(udev_monitor);

        if (udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "block", NULL) < 0 ||
            udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "tty", NULL) < 0 ||
            udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "usb", "usb_device") < 0) {
                printf("filter failed\n");
                goto out;
        }

        if (udev_monitor_enable_receiving(udev_monitor) < 0) {
                printf("bind failed\n");
                goto out;
        }

        memzero(&ep_udev, sizeof(struct epoll_event));
        ep_udev.events = EPOLLIN;
        ep_udev.data.fd = fd_udev;
        if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_udev, &ep_udev) < 0) {
                printf("fail to add fd to epoll: %m\n");
                goto out;
        }

        memzero(&ep_stdin, sizeof(struct epoll_event));
        ep_stdin.events = EPOLLIN;
        ep_stdin.data.fd = STDIN_FILENO;
        if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, STDIN_FILENO, &ep_stdin) < 0) {
                printf("fail to add fd to epoll: %m\n");
                goto out;
        }

        for (;;) {
                int fdcount;
                struct epoll_event ev[4];
                struct udev_device *device;
                int i;

                printf("waiting for events from udev, press ENTER to exit\n");
                fdcount = epoll_wait(fd_ep, ev, ARRAY_SIZE(ev), -1);
                printf("epoll fd count: %i\n", fdcount);

                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN) {
                                device = udev_monitor_receive_device(udev_monitor);
                                if (device == NULL) {
                                        printf("no device from socket\n");
                                        continue;
                                }
                                print_device(device);
                                udev_device_unref(device);
                        } else if (ev[i].data.fd == STDIN_FILENO && ev[i].events & EPOLLIN) {
                                printf("exiting loop\n");
                                goto out;
                        }
                }
        }
out:
        if (fd_ep >= 0)
                close(fd_ep);
        udev_monitor_unref(udev_monitor);
        return 0;
}

static int test_queue(struct udev *udev) {
        struct udev_queue *udev_queue;

        udev_queue = udev_queue_new(udev);
        if (udev_queue == NULL)
                return -1;

        if (udev_queue_get_queue_is_empty(udev_queue))
                printf("queue is empty\n");

        udev_queue_unref(udev_queue);
        return 0;
}

static int test_enumerate(struct udev *udev, const char *subsystem) {
        struct udev_enumerate *udev_enumerate;
        int r;

        printf("enumerate '%s'\n", subsystem == NULL ? "<all>" : subsystem);
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate, subsystem);
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'net' + duplicated scan + null + zero\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate, "net");
        udev_enumerate_scan_devices(udev_enumerate);
        udev_enumerate_scan_devices(udev_enumerate);
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
        udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'block'\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate,"block");
        r = udev_enumerate_add_match_is_initialized(udev_enumerate);
        if (r < 0) {
                udev_enumerate_unref(udev_enumerate);
                return r;
        }
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'not block'\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_nomatch_subsystem(udev_enumerate, "block");
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'pci, mem, vc'\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate, "pci");
        udev_enumerate_add_match_subsystem(udev_enumerate, "mem");
        udev_enumerate_add_match_subsystem(udev_enumerate, "vc");
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'subsystem'\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_scan_subsystems(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        printf("enumerate 'property IF_FS_*=filesystem'\n");
        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return -1;
        udev_enumerate_add_match_property(udev_enumerate, "ID_FS*", "filesystem");
        udev_enumerate_scan_devices(udev_enumerate);
        test_enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);
        return 0;
}

static void test_hwdb(struct udev *udev, const char *modalias) {
        struct udev_hwdb *hwdb;
        struct udev_list_entry *entry;

        hwdb = udev_hwdb_new(udev);

        udev_list_entry_foreach(entry, udev_hwdb_get_properties_list_entry(hwdb, modalias, 0))
                printf("'%s'='%s'\n", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));
        printf("\n");

        hwdb = udev_hwdb_unref(hwdb);
        assert_se(hwdb == NULL);
}

int main(int argc, char *argv[]) {
        struct udev *udev = NULL;
        static const struct option options[] = {
                { "syspath", required_argument, NULL, 'p' },
                { "subsystem", required_argument, NULL, 's' },
                { "debug", no_argument, NULL, 'd' },
                { "help", no_argument, NULL, 'h' },
                { "version", no_argument, NULL, 'V' },
                {}
        };
        const char *syspath = "/devices/virtual/mem/null";
        const char *subsystem = NULL;
        char path[1024];
        int c;

        udev = udev_new();
        printf("context: %p\n", udev);
        if (udev == NULL) {
                printf("no context\n");
                return 1;
        }

        while ((c = getopt_long(argc, argv, "p:s:dhV", options, NULL)) >= 0)
                switch (c) {

                case 'p':
                        syspath = optarg;
                        break;

                case 's':
                        subsystem = optarg;
                        break;

                case 'd':
                        if (log_get_max_level() < LOG_INFO)
                                log_set_max_level(LOG_INFO);
                        break;

                case 'h':
                        printf("--debug --syspath= --subsystem= --help\n");
                        goto out;

                case 'V':
                        printf("%s\n", VERSION);
                        goto out;

                case '?':
                        goto out;

                default:
                        assert_not_reached("Unhandled option code.");
                }


        /* add sys path if needed */
        if (!startswith(syspath, "/sys")) {
                snprintf(path, sizeof(path), "/sys/%s", syspath);
                syspath = path;
        }

        test_device(udev, syspath);
        test_device_devnum(udev);
        test_device_subsys_name(udev);
        test_device_parents(udev, syspath);

        test_enumerate(udev, subsystem);

        test_queue(udev);

        test_hwdb(udev, "usb:v0D50p0011*");

        test_monitor(udev);
out:
        udev_unref(udev);
        return 0;
}
