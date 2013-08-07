/***
  This file is part of systemd.

  Copyright 2012 Kay Sievers <kay@vrfy.org>

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
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <getopt.h>

#include "udev.h"

static struct udev_hwdb *hwdb;

int udev_builtin_hwdb_lookup(struct udev_device *dev,
                             const char *prefix, const char *modalias,
                             const char *filter, bool test) {
        struct udev_list_entry *list;
        struct udev_list_entry *entry;
        int n = 0;

        if (!hwdb)
                return -ENOENT;

        if (prefix) {
                _cleanup_free_ const char *lookup;

                lookup = strjoin(prefix, modalias, NULL);
                if (!lookup)
                        return -ENOMEM;
                list = udev_hwdb_get_properties_list_entry(hwdb, lookup, 0);
        } else
                list = udev_hwdb_get_properties_list_entry(hwdb, modalias, 0);

        udev_list_entry_foreach(entry, list) {
                if (filter && fnmatch(filter, udev_list_entry_get_name(entry), FNM_NOESCAPE) != 0)
                        continue;

                if (udev_builtin_add_property(dev, test,
                                              udev_list_entry_get_name(entry),
                                              udev_list_entry_get_value(entry)) < 0)
                        return -ENOMEM;
                n++;
        }
        return n;
}

static const char *modalias_usb(struct udev_device *dev, char *s, size_t size) {
        const char *v, *p;
        int vn, pn;

        v = udev_device_get_sysattr_value(dev, "idVendor");
        if (!v)
                return NULL;
        p = udev_device_get_sysattr_value(dev, "idProduct");
        if (!p)
                return NULL;
        vn = strtol(v, NULL, 16);
        if (vn <= 0)
                return NULL;
        pn = strtol(p, NULL, 16);
        if (pn <= 0)
                return NULL;
        snprintf(s, size, "usb:v%04Xp%04X*", vn, pn);
        return s;
}

static int udev_builtin_hwdb_search(struct udev_device *dev, struct udev_device *srcdev,
                                    const char *subsystem, const char *prefix,
                                    const char *filter, bool test) {
        struct udev_device *d;
        char s[16];
        int n = 0;

        for (d = srcdev; d; d = udev_device_get_parent(d)) {
                const char *dsubsys;
                const char *modalias = NULL;

                dsubsys = udev_device_get_subsystem(d);
                if (!dsubsys)
                        continue;

                /* look only at devices of a specific subsystem */
                if (subsystem && !streq(dsubsys, subsystem))
                        continue;

                modalias = udev_device_get_property_value(d, "MODALIAS");

                /* the usb_device does not have a modalias, compose one */
                if (!modalias && streq(dsubsys, "usb"))
                        modalias = modalias_usb(d, s, sizeof(s));

                if (!modalias)
                        continue;

                n = udev_builtin_hwdb_lookup(dev, prefix, modalias, filter, test);
                if (n > 0)
                        break;
        }

        return n;
}

static int builtin_hwdb(struct udev_device *dev, int argc, char *argv[], bool test) {
        static const struct option options[] = {
                { "filter", required_argument, NULL, 'f' },
                { "device", required_argument, NULL, 'd' },
                { "subsystem", required_argument, NULL, 's' },
                { "lookup-prefix", required_argument, NULL, 'p' },
                {}
        };
        const char *filter = NULL;
        const char *device = NULL;
        const char *subsystem = NULL;
        const char *prefix = NULL;
        struct udev_device *srcdev;

        if (!hwdb)
                return EXIT_FAILURE;

        for (;;) {
                int option;

                option = getopt_long(argc, argv, "f:d:s:p:", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'f':
                        filter = optarg;
                        break;

                case 'd':
                        device = optarg;
                        break;

                case 's':
                        subsystem = optarg;
                        break;

                case 'p':
                        prefix = optarg;
                        break;
                }
        }

        /* query a specific key given as argument */
        if (argv[optind]) {
                if (udev_builtin_hwdb_lookup(dev, prefix, argv[optind], filter, test) > 0)
                        return EXIT_SUCCESS;
                return EXIT_FAILURE;
        }

        /* read data from another device than the device we will store the data */
        if (device) {
                srcdev = udev_device_new_from_device_id(udev_device_get_udev(dev), device);
                if (!srcdev)
                        return EXIT_FAILURE;
        } else
                srcdev = dev;

        if (udev_builtin_hwdb_search(dev, srcdev, subsystem, prefix, filter, test) > 0)
                return EXIT_SUCCESS;
        return EXIT_FAILURE;
}

/* called at udev startup and reload */
static int builtin_hwdb_init(struct udev *udev)
{
        if (hwdb)
                return 0;
        hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                return -ENOMEM;
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_hwdb_exit(struct udev *udev)
{
        hwdb = udev_hwdb_unref(hwdb);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_hwdb_validate(struct udev *udev)
{
        return udev_hwdb_validate(hwdb);
}

const struct udev_builtin udev_builtin_hwdb = {
        .name = "hwdb",
        .cmd = builtin_hwdb,
        .init = builtin_hwdb_init,
        .exit = builtin_hwdb_exit,
        .validate = builtin_hwdb_validate,
        .help = "hardware database",
};
