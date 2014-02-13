/*
 * Copyright (C) 2008-2009 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "udev.h"
#include "udev-util.h"
#include "util.h"

static int verbose;
static int dry_run;

static void exec_list(struct udev_enumerate *udev_enumerate, const char *action)
{
        struct udev_list_entry *entry;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(udev_enumerate)) {
                char filename[UTIL_PATH_SIZE];
                int fd;

                if (verbose)
                        printf("%s\n", udev_list_entry_get_name(entry));
                if (dry_run)
                        continue;
                strscpyl(filename, sizeof(filename), udev_list_entry_get_name(entry), "/uevent", NULL);
                fd = open(filename, O_WRONLY|O_CLOEXEC);
                if (fd < 0)
                        continue;
                if (write(fd, action, strlen(action)) < 0)
                        log_debug("error writing '%s' to '%s': %m", action, filename);
                close(fd);
        }
}

static const char *keyval(const char *str, const char **val, char *buf, size_t size)
{
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

static void help(void) {
        printf("Usage: udevadm trigger OPTIONS\n"
               "  -v,--verbose                       print the list of devices while running\n"
               "  -n,--dry-run                       do not actually trigger the events\n"
               "  -t,--type=                         type of events to trigger\n"
               "          devices                       sys devices (default)\n"
               "          subsystems                    sys subsystems and drivers\n"
               "  -c,--action=<action>               event action value, default is \"change\"\n"
               "  -s,--subsystem-match=<subsystem>   trigger devices from a matching subsystem\n"
               "  -S,--subsystem-nomatch=<subsystem> exclude devices from a matching subsystem\n"
               "  -a,--attr-match=<file[=<value>]>   trigger devices with a matching attribute\n"
               "  -A,--attr-nomatch=<file[=<value>]> exclude devices with a matching attribute\n"
               "  -p,--property-match=<key>=<value>  trigger devices with a matching property\n"
               "  -g,--tag-match=<key>=<value>       trigger devices with a matching property\n"
               "  -y,--sysname-match=<name>          trigger devices with a matching name\n"
               "  -b,--parent-match=<name>           trigger devices with that parent device\n"
               "  -h,--help\n\n");
}

static int adm_trigger(struct udev *udev, int argc, char *argv[])
{
        static const struct option options[] = {
                { "verbose",           no_argument,       NULL, 'v' },
                { "dry-run",           no_argument,       NULL, 'n' },
                { "type",              required_argument, NULL, 't' },
                { "action",            required_argument, NULL, 'c' },
                { "subsystem-match",   required_argument, NULL, 's' },
                { "subsystem-nomatch", required_argument, NULL, 'S' },
                { "attr-match",        required_argument, NULL, 'a' },
                { "attr-nomatch",      required_argument, NULL, 'A' },
                { "property-match",    required_argument, NULL, 'p' },
                { "tag-match",         required_argument, NULL, 'g' },
                { "sysname-match",     required_argument, NULL, 'y' },
                { "parent-match",      required_argument, NULL, 'b' },
                { "help",              no_argument,       NULL, 'h' },
                {}
        };
        enum {
                TYPE_DEVICES,
                TYPE_SUBSYSTEMS,
        } device_type = TYPE_DEVICES;
        const char *action = "change";
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *udev_enumerate = NULL;
        int c;

        udev_enumerate = udev_enumerate_new(udev);
        if (udev_enumerate == NULL)
                return 1;

        while ((c = getopt_long(argc, argv, "vno:t:c:s:S:a:A:p:g:y:b:h", options, NULL)) >= 0) {
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
                                return 2;
                        }
                        break;
                case 'c':
                        if (!nulstr_contains("add\0" "remove\0" "change\0", optarg)) {
                                log_error("unknown action '%s'", optarg);
                                return 2;
                        } else
                                action = optarg;

                        break;
                case 's':
                        udev_enumerate_add_match_subsystem(udev_enumerate, optarg);
                        break;
                case 'S':
                        udev_enumerate_add_nomatch_subsystem(udev_enumerate, optarg);
                        break;
                case 'a':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_match_sysattr(udev_enumerate, key, val);
                        break;
                case 'A':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_nomatch_sysattr(udev_enumerate, key, val);
                        break;
                case 'p':
                        key = keyval(optarg, &val, buf, sizeof(buf));
                        udev_enumerate_add_match_property(udev_enumerate, key, val);
                        break;
                case 'g':
                        udev_enumerate_add_match_tag(udev_enumerate, optarg);
                        break;
                case 'y':
                        udev_enumerate_add_match_sysname(udev_enumerate, optarg);
                        break;
                case 'b': {
                        char path[UTIL_PATH_SIZE];
                        struct udev_device *dev;

                        /* add sys dir if needed */
                        if (!startswith(optarg, "/sys"))
                                strscpyl(path, sizeof(path), "/sys", optarg, NULL);
                        else
                                strscpy(path, sizeof(path), optarg);
                        util_remove_trailing_chars(path, '/');
                        dev = udev_device_new_from_syspath(udev, path);
                        if (dev == NULL) {
                                log_error("unable to open the device '%s'", optarg);
                                return 2;
                        }
                        udev_enumerate_add_match_parent(udev_enumerate, dev);
                        /* drop reference immediately, enumerate pins the device as long as needed */
                        udev_device_unref(dev);
                        break;
                }
                case 'h':
                        help();
                        return 0;
                case '?':
                        return 1;
                default:
                        assert_not_reached("Unknown option");
                }
        }

        if (optind < argc) {
                fprintf(stderr, "Extraneous argument: '%s'\n", argv[optind]);
                return 1;
        }

        switch (device_type) {
        case TYPE_SUBSYSTEMS:
                udev_enumerate_scan_subsystems(udev_enumerate);
                exec_list(udev_enumerate, action);
                return 0;
        case TYPE_DEVICES:
                udev_enumerate_scan_devices(udev_enumerate);
                exec_list(udev_enumerate, action);
                return 0;
        default:
                assert_not_reached("device_type");
        }
}

const struct udevadm_cmd udevadm_trigger = {
        .name = "trigger",
        .cmd = adm_trigger,
        .help = "request events from the kernel",
};
