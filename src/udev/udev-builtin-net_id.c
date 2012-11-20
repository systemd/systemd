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

/*
 * eno<index> -- ethernet on-board
 * ID_NET_NAME_FIRMWARE=eno1
 *
 * enp<pci bus number>s<slot>f<function> -- physical location/path
 * ID_NET_NAME_PATH=enp19s0f0
 *
 * enm<MAC address> -- MAC address
 * ID_NET_NAME_MAC=enxf0def180d479
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "udev.h"

static int dev_pci(struct udev_device *dev, const char *prefix, bool test) {
        struct udev_device *d;
        unsigned int bus;
        unsigned int slot;
        unsigned int func;
        const char *index;
        int err;

        /* skip other buses than direct PCI parents */
        d = udev_device_get_parent(dev);
        if (!d || !streq("pci", udev_device_get_subsystem(d)))
                return -ENOENT;

        /* find SMBIOS type 41 entries for on-board devices */
        index = udev_device_get_sysattr_value(d, "index");
        if (index) {
                unsigned int idx;

                idx = strtoul(index, NULL, 0);
                if (idx > 0) {
                        const char *label;
                        char s[16];

                        snprintf(s, sizeof(s), "%so%d", prefix, idx);
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_FIRMWARE", s);

                        label = udev_device_get_sysattr_value(d, "label");
                        if (label)
                                udev_builtin_add_property(dev, test, "ID_NET_LABEL_FIRMWARE", label);
                }
        }

        /* compose a name based on the PCI bus location */
        if (sscanf(udev_device_get_sysname(d), "0000:%x:%x.%d", &bus, &slot, &func) == 3) {
                char str[16];

                snprintf(str, sizeof(str), "%sp%ds%df%d", prefix, bus, slot, func);
                err = udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
                if (err < 0)
                        return err;
        }
        return 0;
}

static int dev_mac(struct udev_device *dev, const char *prefix, bool test) {
        const char *s;
        unsigned int i;
        unsigned int a1, a2, a3, a4, a5, a6;
        char str[16];
        int err;

        /* check for NET_ADDR_PERM, skip random MAC addresses */
        s = udev_device_get_sysattr_value(dev, "addr_assign_type");
        if (!s)
                return EXIT_FAILURE;
        i = strtoul(s, NULL, 0);
        if (i != 0)
                return 0;

        s = udev_device_get_sysattr_value(dev, "address");
        if (!s)
                return -ENOENT;
        if (sscanf(s, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6)
                return -EINVAL;

        /* skip empty MAC addresses */
        if (a1 + a2 + a3 + a4 + a5 + a6 == 0)
                return -EINVAL;

        /* add IEEE Organizationally Unique Identifier */
        snprintf(str, sizeof(str), "OUI:%X%X%X", a1, a2, a3);
        udev_builtin_hwdb_lookup(dev, str, test);

        snprintf(str, sizeof(str), "%sx%x%x%x%x%x%x", prefix, a1, a2, a3, a4, a5, a6);
        err = udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);
        if (err < 0)
                return err;
        return 0;
}

static int builtin_net_id(struct udev_device *dev, int argc, char *argv[], bool test) {
        const char *s;
        unsigned int i;
        const char *devtype;
        const char *prefix = "en";

        /* handle only ARPHRD_ETHER devices */
        s = udev_device_get_sysattr_value(dev, "type");
        if (!s)
                return EXIT_FAILURE;
        i = strtoul(s, NULL, 0);
        if (i != 1)
                return 0;

        devtype = udev_device_get_devtype(dev);
        if (devtype) {
                if (streq("wlan", devtype))
                        prefix = "wl";
                else if (streq("wwan", devtype))
                        prefix = "ww";
        }

        dev_pci(dev, prefix, test);
        dev_mac(dev, prefix, test);
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .help = "network device properties",
};
