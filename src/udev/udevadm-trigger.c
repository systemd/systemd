/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fd-util.h"
#include "set.h"
#include "string-util.h"
#include "udev.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "util.h"

static int verbose;
static int dry_run;

static int exec_list(struct udev_enumerate *udev_enumerate, const char *action, Set *settle_set) {
        struct udev_list_entry *entry;
        int r;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate)) {
                char filename[UTIL_PATH_SIZE];
                const char *syspath;
                _cleanup_close_ int fd = -1;

                syspath = udev_list_entry_get_name(entry);
                if (verbose)
                        printf("%s\n", syspath);
                if (dry_run)
                        continue;

                strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);
                fd = open(filename, O_WRONLY|O_CLOEXEC);
                if (fd < 0)
                        continue;

                if (settle_set) {
                        r = set_put_strdup(settle_set, syspath);
                        if (r < 0)
                                return log_oom();
                }

                if (write(fd, action, strlen(action)) < 0)
                        log_debug_errno(errno, "error writing '%s' to '%s': %m", action, filename);
        }

        return 0;
}

static const char *keyval(const char *str, const char **val, char *buf, size_t size) {
        char *pos;

        strscpy(buf, size,str);
        pos = strchr(buf, '=');
        if (pos != NULL) {
                pos[0] = 0;
                pos++;
        }
        *val = pos;
        return buf;
}

static int help(void) {
        printf("%s trigger [OPTIONS] DEVPATH\n\n"
               "Request events from the kernel.\n\n"
               "  -h --help                         Show this help\n"
               "  -V --version                      Show package version\n"
               "  -v --verbose                      Print the list of devices while running\n"
               "  -n --dry-run                      Do not actually trigger the events\n"
               "  -t --type=                        Type of events to trigger\n"
               "          devices                     sysfs devices (default)\n"
               "          subsystems                  sysfs subsystems and drivers\n"
               "  -c --action=ACTION                Event action value, default is \"change\"\n"
               "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
               "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
               "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
               "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
               "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
               "  -g --tag-match=KEY=VALUE          Trigger devices with a matching property\n"
               "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
               "     --name-match=NAME              Trigger devices with this /dev name\n"
               "  -b --parent-match=NAME            Trigger devices with that parent device\n"
               "  -w --settle                       Wait for the triggered events to complete\n"
               , program_invocation_short_name);

        return 0;
}

int trigger_main(int argc, char *argv[], void *userdata) {
        enum {
                ARG_NAME = 0x100,
        };

        static const struct option options[] = {
                { "verbose",           no_argument,       NULL, 'v'      },
                { "dry-run",           no_argument,       NULL, 'n'      },
                { "type",              required_argument, NULL, 't'      },
                { "action",            required_argument, NULL, 'c'      },
                { "subsystem-match",   required_argument, NULL, 's'      },
                { "subsystem-nomatch", required_argument, NULL, 'S'      },
                { "attr-match",        required_argument, NULL, 'a'      },
                { "attr-nomatch",      required_argument, NULL, 'A'      },
                { "property-match",    required_argument, NULL, 'p'      },
                { "tag-match",         required_argument, NULL, 'g'      },
                { "sysname-match",     required_argument, NULL, 'y'      },
                { "name-match",        required_argument, NULL, ARG_NAME },
                { "parent-match",      required_argument, NULL, 'b'      },
                { "settle",            no_argument,       NULL, 'w'      },
                { "version",           no_argument,       NULL, 'V'      },
                { "help",              no_argument,       NULL, 'h'      },
                {}
        };
        enum {
                TYPE_DEVICES,
                TYPE_SUBSYSTEMS,
        } device_type = TYPE_DEVICES;
        const char *action = "change";
        _cleanup_(udev_enumerate_unrefp) struct udev_enumerate *udev_enumerate = NULL;
        _cleanup_(udev_monitor_unrefp) struct udev_monitor *udev_monitor = NULL;
        _cleanup_close_ int fd_ep = -1;
        int fd_udev = -1;
        struct epoll_event ep_udev;
        bool settle = false;
        _cleanup_set_free_free_ Set *settle_set = NULL;
        int c, r;

        udev_enumerate = udev_enumerate_new(NULL);
        if (!udev_enumerate)
                return -errno;

        while ((c = getopt_long(argc, argv, "vnt:c:s:S:a:A:p:g:y:b:wVh", options, NULL)) >= 0) {
                const char *key;
                const char *val;
                char buf[UTIL_PATH_SIZE];

                switch (c) {
                case 'v':
                        verbose = 1;
                        break;
                case 'n':
                        dry_run = 1;
                        break;
                case 't':
                        if (streq(optarg, "devices"))
                                device_type = TYPE_DEVICES;
                        else if (streq(optarg, "subsystems"))
                                device_type = TYPE_SUBSYSTEMS;
                        else {
                                log_error("unknown type --type=%s", optarg);
                                return -EINVAL;
                        }
                        break;
                case 'c':
                        if (STR_IN_SET(optarg, "add", "remove", "change"))
                                action = optarg;
                        else {
                                log_error("unknown action '%s'", optarg);
                                return -EINVAL;
                        }

                        break;
                case 's':
                        r = udev_enumerate_add_match_subsystem(udev_enumerate, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add subsystem match '%s': %m", optarg);
                        break;
                case 'S':
                        r = udev_enumerate_add_nomatch_subsystem(udev_enumerate, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add negative subsystem match '%s': %m", optarg);
                        break;
                case 'a':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = udev_enumerate_add_match_sysattr(udev_enumerate, key, val);
                        if (r < 0)
                                return log_error_errno(r, "could not add sysattr match '%s=%s': %m", key, val);
                        break;
                case 'A':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = udev_enumerate_add_nomatch_sysattr(udev_enumerate, key, val);
                        if (r < 0)
                                return log_error_errno(r, "could not add negative sysattr match '%s=%s': %m", key, val);
                        break;
                case 'p':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = udev_enumerate_add_match_property(udev_enumerate, key, val);
                        if (r < 0)
                                return log_error_errno(r, "could not add property match '%s=%s': %m", key, val);
                        break;
                case 'g':
                        r = udev_enumerate_add_match_tag(udev_enumerate, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add tag match '%s': %m", optarg);
                        break;
                case 'y':
                        r = udev_enumerate_add_match_sysname(udev_enumerate, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add sysname match '%s': %m", optarg);
                        break;
                case 'b': {
                        _cleanup_(udev_device_unrefp) struct udev_device *dev;

                        dev = find_device(optarg, "/sys");
                        if (!dev)
                                return log_error_errno(errno, "unable to open the device '%s'", optarg);

                        r = udev_enumerate_add_match_parent(udev_enumerate, dev);
                        if (r < 0)
                                return log_error_errno(r, "could not add parent match '%s': %m", optarg);
                        break;
                }
                case 'w':
                        settle = true;
                        break;

                case ARG_NAME: {
                        _cleanup_(udev_device_unrefp) struct udev_device *dev;

                        dev = find_device(optarg, "/dev/");
                        if (!dev)
                                return log_error_errno(errno, "unable to open the device '%s'", optarg);

                        r = udev_enumerate_add_match_parent(udev_enumerate, dev);
                        if (r < 0)
                                return log_error_errno(r, "could not add parent match '%s': %m", optarg);
                        break;
                }

                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }
        }

        for (; optind < argc; optind++) {
                _cleanup_(udev_device_unrefp) struct udev_device *dev;

                dev = find_device(argv[optind], NULL);
                if (!dev) {
                        log_error("unable to open the device '%s'", argv[optind]);
                        return -EINVAL;
                }

                r = udev_enumerate_add_match_parent(udev_enumerate, dev);
                if (r < 0)
                        return log_error_errno(r, "could not add tag match '%s': %m", optarg);
        }

        if (settle) {
                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0)
                        return log_error_errno(errno, "error creating epoll fd: %m");

                udev_monitor = udev_monitor_new_from_netlink(NULL, "udev");
                if (!udev_monitor)
                        return log_error_errno(errno, "error: unable to create netlink socket: %m");

                fd_udev = udev_monitor_get_fd(udev_monitor);

                r = udev_monitor_enable_receiving(udev_monitor);
                if (r < 0)
                        return log_error_errno(r, "error: unable to subscribe to udev events: %m");

                ep_udev = (struct epoll_event) { .events = EPOLLIN, .data.fd = fd_udev };
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_udev, &ep_udev) < 0)
                        return log_error_errno(errno, "fail to add fd to epoll: %m");

                settle_set = set_new(&string_hash_ops);
                if (!settle_set)
                        return log_oom();
        }

        switch (device_type) {
        case TYPE_SUBSYSTEMS:
                udev_enumerate_scan_subsystems(udev_enumerate);
                break;
        case TYPE_DEVICES:
                udev_enumerate_scan_devices(udev_enumerate);
                break;
        default:
                assert_not_reached("device_type");
        }
        r = exec_list(udev_enumerate, action, settle_set);
        if (r < 0)
                return r;

        while (!set_isempty(settle_set)) {
                int fdcount;
                struct epoll_event ev[4];
                int i;

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), -1);
                if (fdcount < 0) {
                        if (errno != EINTR)
                                log_error_errno(errno, "error receiving uevent message: %m");
                        continue;
                }

                for (i = 0; i < fdcount; i++) {
                        if (ev[i].data.fd == fd_udev && ev[i].events & EPOLLIN) {
                                _cleanup_(udev_device_unrefp) struct udev_device *device;
                                const char *syspath = NULL;

                                device = udev_monitor_receive_device(udev_monitor);
                                if (!device)
                                        continue;

                                syspath = udev_device_get_syspath(device);
                                if (verbose)
                                        printf("settle %s\n", syspath);
                                if (!set_remove(settle_set, syspath))
                                        log_debug("Got epoll event on syspath %s not present in syspath set", syspath);
                        }
                }
        }

        return 0;
}
