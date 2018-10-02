/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "device-enumerator-private.h"
#include "device-monitor-private.h"
#include "fd-util.h"
#include "libudev-private.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "udevadm.h"
#include "udevadm-util.h"

static bool arg_verbose = false;
static bool arg_dry_run = false;

static int exec_list(sd_device_enumerator *e, const char *action, Set *settle_set) {
        sd_device *d;
        int r;

        FOREACH_DEVICE_AND_SUBSYSTEM(e, d) {
                char filename[UTIL_PATH_SIZE];
                const char *syspath;
                _cleanup_close_ int fd = -1;

                if (sd_device_get_syspath(d, &syspath) < 0)
                        continue;

                if (arg_verbose)
                        printf("%s\n", syspath);
                if (arg_dry_run)
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
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_set_free_free_ Set *settle_set = NULL;
        _cleanup_close_ int fd_ep = -1;
        struct epoll_event ep_monitor;
        int c, r, fd_monitor = -1;
        bool settle = false;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        while ((c = getopt_long(argc, argv, "vnt:c:s:S:a:A:p:g:y:b:wVh", options, NULL)) >= 0) {
                const char *key;
                const char *val;
                char buf[UTIL_PATH_SIZE];

                switch (c) {
                case 'v':
                        arg_verbose = true;
                        break;
                case 'n':
                        arg_dry_run = true;
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
                        r = sd_device_enumerator_add_match_subsystem(e, optarg, true);
                        if (r < 0)
                                return log_error_errno(r, "could not add subsystem match '%s': %m", optarg);
                        break;
                case 'S':
                        r = sd_device_enumerator_add_match_subsystem(e, optarg, false);
                        if (r < 0)
                                return log_error_errno(r, "could not add negative subsystem match '%s': %m", optarg);
                        break;
                case 'a':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = sd_device_enumerator_add_match_sysattr(e, key, val, true);
                        if (r < 0)
                                return log_error_errno(r, "could not add sysattr match '%s=%s': %m", key, val);
                        break;
                case 'A':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = sd_device_enumerator_add_match_sysattr(e, key, val, false);
                        if (r < 0)
                                return log_error_errno(r, "could not add negative sysattr match '%s=%s': %m", key, val);
                        break;
                case 'p':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        r = sd_device_enumerator_add_match_property(e, key, val);
                        if (r < 0)
                                return log_error_errno(r, "could not add property match '%s=%s': %m", key, val);
                        break;
                case 'g':
                        r = sd_device_enumerator_add_match_tag(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add tag match '%s': %m", optarg);
                        break;
                case 'y':
                        r = sd_device_enumerator_add_match_sysname(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "could not add sysname match '%s': %m", optarg);
                        break;
                case 'b': {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, "/sys", &dev);
                        if (r < 0)
                                return log_error_errno(r, "unable to open the device '%s'", optarg);

                        r = sd_device_enumerator_add_match_parent(e, dev);
                        if (r < 0)
                                return log_error_errno(r, "could not add parent match '%s': %m", optarg);
                        break;
                }
                case 'w':
                        settle = true;
                        break;

                case ARG_NAME: {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, "/dev/", &dev);
                        if (r < 0)
                                return log_error_errno(r, "unable to open the device '%s'", optarg);

                        r = sd_device_enumerator_add_match_parent(e, dev);
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
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                r = find_device(argv[optind], NULL, &dev);
                if (r < 0)
                        return log_error_errno(r, "unable to open the device '%s'", argv[optind]);

                r = sd_device_enumerator_add_match_parent(e, dev);
                if (r < 0)
                        return log_error_errno(r, "could not add parent match '%s': %m", argv[optind]);
        }

        if (settle) {
                fd_ep = epoll_create1(EPOLL_CLOEXEC);
                if (fd_ep < 0)
                        return log_error_errno(errno, "error creating epoll fd: %m");

                r = sd_device_monitor_new(&m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create device monitor object: %m");

                fd_monitor = device_monitor_get_fd(m);
                if (fd_monitor < 0)
                        return log_error_errno(fd_monitor, "Failed to get monitor fd: %m");

                r = device_monitor_enable_receiving(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to subscribe udev events: %m");

                ep_monitor = (struct epoll_event) {
                        .events = EPOLLIN,
                        .data.fd = fd_monitor,
                };
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_monitor, &ep_monitor) < 0)
                        return log_error_errno(errno, "Failed to add fd to epoll: %m");

                settle_set = set_new(&string_hash_ops);
                if (!settle_set)
                        return log_oom();
        }

        switch (device_type) {
        case TYPE_SUBSYSTEMS:
                r = device_enumerator_scan_subsystems(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan subsystems: %m");
                break;
        case TYPE_DEVICES:
                r = device_enumerator_scan_devices(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan devices: %m");
                break;
        default:
                assert_not_reached("device_type");
        }
        r = exec_list(e, action, settle_set);
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
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                        const char *syspath = NULL;

                        if (!(ev[i].data.fd == fd_monitor && ev[i].events & EPOLLIN))
                                continue;

                        if (device_monitor_receive_device(m, &dev) <= 0)
                                continue;

                        if (sd_device_get_syspath(dev, &syspath) < 0)
                                continue;

                        if (arg_verbose)
                                printf("settle %s\n", syspath);

                        if (!set_remove(settle_set, syspath))
                                log_debug("Got epoll event on syspath %s not present in syspath set", syspath);
                }
        }

        return 0;
}
