/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "device-util.h"
#include "hwdb-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "udev-builtin.h"

static sd_hwdb *hwdb;

int udev_builtin_hwdb_lookup(sd_device *dev,
                             const char *prefix, const char *modalias,
                             const char *filter, bool test) {
        _cleanup_free_ char *lookup = NULL;
        const char *key, *value;
        int n = 0, r;

        if (!hwdb)
                return -ENOENT;

        if (prefix) {
                lookup = strjoin(prefix, modalias);
                if (!lookup)
                        return -ENOMEM;
                modalias = lookup;
        }

        SD_HWDB_FOREACH_PROPERTY(hwdb, modalias, key, value) {
                if (filter && fnmatch(filter, key, FNM_NOESCAPE) != 0)
                        continue;

                r = udev_builtin_add_property(dev, test, key, value);
                if (r < 0)
                        return r;
                n++;
        }
        return n;
}

static const char *modalias_usb(sd_device *dev, char *s, size_t size) {
        const char *v, *p;
        uint16_t vn, pn;

        if (sd_device_get_sysattr_value(dev, "idVendor", &v) < 0)
                return NULL;
        if (sd_device_get_sysattr_value(dev, "idProduct", &p) < 0)
                return NULL;
        if (safe_atoux16(v, &vn) < 0)
                return NULL;
        if (safe_atoux16(p, &pn) < 0)
                return NULL;
        snprintf(s, size, "usb:v%04Xp%04X*", vn, pn);
        return s;
}

static int udev_builtin_hwdb_search(sd_device *dev, sd_device *srcdev,
                                    const char *subsystem, const char *prefix,
                                    const char *filter, bool test) {
        sd_device *d;
        char s[16];
        bool last = false;
        int r = 0;

        assert(dev);

        if (!srcdev)
                srcdev = dev;

        for (d = srcdev; d; ) {
                const char *dsubsys, *devtype, *modalias = NULL;

                if (sd_device_get_subsystem(d, &dsubsys) < 0)
                        goto next;

                /* look only at devices of a specific subsystem */
                if (subsystem && !streq(dsubsys, subsystem))
                        goto next;

                (void) sd_device_get_property_value(d, "MODALIAS", &modalias);

                if (streq(dsubsys, "usb") &&
                    sd_device_get_devtype(d, &devtype) >= 0 &&
                    streq(devtype, "usb_device")) {
                        /* if the usb_device does not have a modalias, compose one */
                        if (!modalias)
                                modalias = modalias_usb(d, s, sizeof(s));

                        /* avoid looking at any parent device, they are usually just a USB hub */
                        last = true;
                }

                if (!modalias)
                        goto next;

                r = udev_builtin_hwdb_lookup(dev, prefix, modalias, filter, test);
                if (r > 0)
                        break;

                if (last)
                        break;
next:
                if (sd_device_get_parent(d, &d) < 0)
                        break;
        }

        return r;
}

static int builtin_hwdb(sd_device *dev, int argc, char *argv[], bool test) {
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
        _cleanup_(sd_device_unrefp) sd_device *srcdev = NULL;
        int r;

        if (!hwdb)
                return -EINVAL;

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
                r = udev_builtin_hwdb_lookup(dev, prefix, argv[optind], filter, test);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to lookup hwdb: %m");
                if (r == 0)
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENODATA), "No entry found from hwdb.");
                return r;
        }

        /* read data from another device than the device we will store the data */
        if (device) {
                r = sd_device_new_from_device_id(&srcdev, device);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to create sd_device object '%s': %m", device);
        }

        r = udev_builtin_hwdb_search(dev, srcdev, subsystem, prefix, filter, test);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to lookup hwdb: %m");
        if (r == 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENODATA), "No entry found from hwdb.");
        return r;
}

/* called at udev startup and reload */
static int builtin_hwdb_init(void) {
        int r;

        if (hwdb)
                return 0;

        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return r;

        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_hwdb_exit(void) {
        hwdb = sd_hwdb_unref(hwdb);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_hwdb_validate(void) {
        return hwdb_validate(hwdb);
}

const UdevBuiltin udev_builtin_hwdb = {
        .name = "hwdb",
        .cmd = builtin_hwdb,
        .init = builtin_hwdb_init,
        .exit = builtin_hwdb_exit,
        .validate = builtin_hwdb_validate,
        .help = "Hardware database",
};
