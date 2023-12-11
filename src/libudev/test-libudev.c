/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "alloc-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "libudev-list-internal.h"
#include "libudev-util.h"
#include "log.h"
#include "main-func.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"
#include "version.h"

static bool arg_monitor = false;

static void print_device(struct udev_device *device) {
        const char *str;
        dev_t devnum;
        int count;
        struct udev_list_entry *list_entry;

        log_info("*** device: %p ***", device);
        str = udev_device_get_action(device);
        if (str)
                log_info("action:    '%s'", str);

        str = udev_device_get_syspath(device);
        log_info("syspath:   '%s'", str);

        str = udev_device_get_sysname(device);
        log_info("sysname:   '%s'", str);

        str = udev_device_get_sysnum(device);
        if (str)
                log_info("sysnum:    '%s'", str);

        str = udev_device_get_devpath(device);
        log_info("devpath:   '%s'", str);

        str = udev_device_get_subsystem(device);
        if (str)
                log_info("subsystem: '%s'", str);

        str = udev_device_get_devtype(device);
        if (str)
                log_info("devtype:   '%s'", str);

        str = udev_device_get_driver(device);
        if (str)
                log_info("driver:    '%s'", str);

        str = udev_device_get_devnode(device);
        if (str)
                log_info("devname:   '%s'", str);

        devnum = udev_device_get_devnum(device);
        if (major(devnum) > 0)
                log_info("devnum:    %u:%u", major(devnum), minor(devnum));

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
                log_info("link:      '%s'", udev_list_entry_get_name(list_entry));
                count++;
        }
        if (count > 0)
                log_info("found %i links", count);

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
                log_info("property:  '%s=%s'",
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));
                count++;
        }
        if (count > 0)
                log_info("found %i properties", count);

        str = udev_device_get_property_value(device, "MAJOR");
        if (str)
                log_info("MAJOR: '%s'", str);

        str = udev_device_get_sysattr_value(device, "dev");
        if (str)
                log_info("attr{dev}: '%s'", str);
}

static void test_device(struct udev *udev, const char *syspath) {
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;

        log_info("/* %s, device %s */", __func__, syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (device)
                print_device(device);
        else
                log_warning_errno(errno, "udev_device_new_from_syspath: %m");
}

static void test_device_parents(struct udev *udev, const char *syspath) {
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;
        struct udev_device *device_parent;

        log_info("/* %s, device %s */", __func__, syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (!device)
                return;

        log_info("looking at parents");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);

        log_info("looking at parents again");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);
}

static void test_device_devnum(struct udev *udev) {
        dev_t devnum = makedev(1, 3);
        _cleanup_(udev_device_unrefp) struct udev_device *device;

        log_info("/* %s, device " DEVNUM_FORMAT_STR " */", __func__, DEVNUM_FORMAT_VAL(devnum));

        device = udev_device_new_from_devnum(udev, 'c', devnum);
        if (device)
                print_device(device);
        else
                log_warning_errno(errno, "udev_device_new_from_devnum: %m");
}

static void test_device_subsys_name(struct udev *udev, const char *subsys, const char *dev) {
        _cleanup_(udev_device_unrefp) struct udev_device *device;

        log_info("looking up device: '%s:%s'", subsys, dev);
        device = udev_device_new_from_subsystem_sysname(udev, subsys, dev);
        if (!device)
                log_warning_errno(errno, "udev_device_new_from_subsystem_sysname: %m");
        else
                print_device(device);
}

static int enumerate_print_list(struct udev_enumerate *enumerate) {
        struct udev_list_entry *list_entry;
        int count = 0;

        udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(enumerate)) {
                struct udev_device *device;

                device = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
                                                      udev_list_entry_get_name(list_entry));
                if (device) {
                        log_info("device: '%s' (%s)",
                                 udev_device_get_syspath(device),
                                 udev_device_get_subsystem(device));
                        udev_device_unref(device);
                        count++;
                }
        }
        log_info("found %i devices", count);
        return count;
}

static void test_monitor(struct udev *udev) {
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *udev_monitor = NULL;
        _cleanup_close_ int fd_ep = -EBADF;
        int fd_udev;
        struct epoll_event ep_udev = {
                .events = EPOLLIN,
        }, ep_stdin = {
                .events = EPOLLIN,
                .data.fd = STDIN_FILENO,
        };

        log_info("/* %s */", __func__);

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        assert_se(fd_ep >= 0);

        udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
        assert_se(udev_monitor != NULL);

        fd_udev = udev_monitor_get_fd(udev_monitor);
        ep_udev.data.fd = fd_udev;

        assert_se(udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "block", NULL) >= 0);
        assert_se(udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "tty", NULL) >= 0);
        assert_se(udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "usb", "usb_device") >= 0);

        assert_se(udev_monitor_enable_receiving(udev_monitor) >= 0);

        assert_se(epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_udev, &ep_udev) >= 0);
        assert_se(epoll_ctl(fd_ep, EPOLL_CTL_ADD, STDIN_FILENO, &ep_stdin) >= 0);

        for (;;) {
                int fdcount;
                struct epoll_event ev[4];
                struct udev_device *device;
                int i;

                printf("waiting for events from udev, press ENTER to exit\n");
                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                printf("epoll fd count: %i\n", fdcount);

                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN) {
                                device = udev_monitor_receive_device(udev_monitor);
                                if (!device) {
                                        printf("no device from socket\n");
                                        continue;
                                }
                                print_device(device);
                                udev_device_unref(device);
                        } else if (ev[i].data.fd == STDIN_FILENO && ev[i].events & EPOLLIN) {
                                printf("exiting loop\n");
                                return;
                        }
                }
        }
}

static void test_queue(struct udev *udev) {
        struct udev_queue *udev_queue;
        bool empty;

        log_info("/* %s */", __func__);

        assert_se(udev_queue = udev_queue_new(udev));

        empty = udev_queue_get_queue_is_empty(udev_queue);
        log_info("queue is %s", empty ? "empty" : "not empty");
        udev_queue_unref(udev_queue);
}

static int test_enumerate(struct udev *udev, const char *subsystem) {
        struct udev_enumerate *udev_enumerate;
        int r;

        log_info("/* %s */", __func__);

        log_info("enumerate '%s'", subsystem == NULL ? "<all>" : subsystem);
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate, subsystem);
        udev_enumerate_scan_devices(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'net' + duplicated scan + null + zero");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
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
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'block'");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate,"block");
        r = udev_enumerate_add_match_is_initialized(udev_enumerate);
        if (r < 0) {
                udev_enumerate_unref(udev_enumerate);
                return r;
        }
        udev_enumerate_scan_devices(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'not block'");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_add_nomatch_subsystem(udev_enumerate, "block");
        udev_enumerate_scan_devices(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'pci, mem, vc'");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_add_match_subsystem(udev_enumerate, "pci");
        udev_enumerate_add_match_subsystem(udev_enumerate, "mem");
        udev_enumerate_add_match_subsystem(udev_enumerate, "vc");
        udev_enumerate_scan_devices(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'subsystem'");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_scan_subsystems(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);

        log_info("enumerate 'property IF_FS_*=filesystem'");
        udev_enumerate = udev_enumerate_new(udev);
        if (!udev_enumerate)
                return -1;
        udev_enumerate_add_match_property(udev_enumerate, "ID_FS*", "filesystem");
        udev_enumerate_scan_devices(udev_enumerate);
        enumerate_print_list(udev_enumerate);
        udev_enumerate_unref(udev_enumerate);
        return 0;
}

static void test_hwdb(struct udev *udev, const char *modalias) {
        struct udev_hwdb *hwdb;
        struct udev_list_entry *entry;

        log_info("/* %s */", __func__);

        hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                log_warning_errno(errno, "Failed to open hwdb: %m");

        SAVE_ASSERT_RETURN_IS_CRITICAL;
        log_set_assert_return_is_critical(hwdb);

        udev_list_entry_foreach(entry, udev_hwdb_get_properties_list_entry(hwdb, modalias, 0))
                log_info("'%s'='%s'", udev_list_entry_get_name(entry), udev_list_entry_get_value(entry));

        hwdb = udev_hwdb_unref(hwdb);
        assert_se(hwdb == NULL);
}

static void test_list(void) {
        _cleanup_(udev_list_freep) struct udev_list *list = NULL;
        struct udev_list_entry *e;

        /* empty list */
        assert_se(list = udev_list_new(false));
        assert_se(!udev_list_get_entry(list));
        list = udev_list_free(list);

        /* unique == false */
        assert_se(list = udev_list_new(false));
        assert_se(udev_list_entry_add(list, "aaa", "hoge"));
        assert_se(udev_list_entry_add(list, "aaa", "hogehoge"));
        assert_se(udev_list_entry_add(list, "bbb", "foo"));
        e = udev_list_get_entry(list);
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "aaa"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "hoge"));
        e = udev_list_entry_get_next(e);
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "aaa"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "hogehoge"));
        e = udev_list_entry_get_next(e);
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "bbb"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "foo"));
        assert_se(!udev_list_entry_get_next(e));

        assert_se(!udev_list_entry_get_by_name(e, "aaa"));
        assert_se(!udev_list_entry_get_by_name(e, "bbb"));
        assert_se(!udev_list_entry_get_by_name(e, "ccc"));
        list = udev_list_free(list);

        /* unique == true */
        assert_se(list = udev_list_new(true));
        assert_se(udev_list_entry_add(list, "aaa", "hoge"));
        assert_se(udev_list_entry_add(list, "aaa", "hogehoge"));
        assert_se(udev_list_entry_add(list, "bbb", "foo"));
        e = udev_list_get_entry(list);
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "aaa"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "hogehoge"));
        e = udev_list_entry_get_next(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "bbb"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "foo"));
        assert_se(!udev_list_entry_get_next(e));

        e = udev_list_entry_get_by_name(e, "bbb");
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "bbb"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "foo"));
        e = udev_list_entry_get_by_name(e, "aaa");
        assert_se(e);
        assert_se(streq_ptr(udev_list_entry_get_name(e), "aaa"));
        assert_se(streq_ptr(udev_list_entry_get_value(e), "hogehoge"));
        assert_se(!udev_list_entry_get_by_name(e, "ccc"));
}

static int parse_args(int argc, char *argv[], const char **syspath, const char **subsystem) {
        static const struct option options[] = {
                { "syspath",   required_argument, NULL, 'p' },
                { "subsystem", required_argument, NULL, 's' },
                { "debug",     no_argument,       NULL, 'd' },
                { "help",      no_argument,       NULL, 'h' },
                { "version",   no_argument,       NULL, 'V' },
                { "monitor",   no_argument,       NULL, 'm' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "p:s:dhVm", options, NULL)) >= 0)
                switch (c) {
                case 'p':
                        *syspath = optarg;
                        break;

                case 's':
                        *subsystem = optarg;
                        break;

                case 'd':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'h':
                        printf("--debug --syspath= --subsystem= --help\n");
                        return 0;

                case 'V':
                        printf("%s\n", GIT_VERSION);
                        return 0;

                case 'm':
                        arg_monitor = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(udev_unrefp) struct udev *udev = NULL;

        const char *syspath = "/devices/virtual/mem/null";
        const char *subsystem = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        r = parse_args(argc, argv, &syspath, &subsystem);
        if (r <= 0)
                return r;

        assert_se(udev = udev_new());

        /* add sys path if needed */
        if (!startswith(syspath, "/sys"))
                syspath = strjoina("/sys/", syspath);

        test_device(udev, syspath);
        test_device_devnum(udev);
        test_device_subsys_name(udev, "block", "sda");
        test_device_subsys_name(udev, "subsystem", "pci");
        test_device_subsys_name(udev, "drivers", "scsi:sd");
        test_device_subsys_name(udev, "module", "printk");
        test_device_parents(udev, syspath);

        test_enumerate(udev, subsystem);

        test_queue(udev);

        test_hwdb(udev, "usb:v0D50p0011*");

        if (arg_monitor)
                test_monitor(udev);

        test_list();

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
