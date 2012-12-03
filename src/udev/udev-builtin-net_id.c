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
 * predictable network interface device names based on:
 *  - firmware/bios-provided index numbers for on-board devices
 *  - firmware-provided pci-express hotplug slot index number
 *  - physical/geographical location of the hardware
 *  - the interface's MAC address
 *
 * two character prefixes based on the type of interface:
 *   en -- ethernet
 *   wl -- wlan
 *   ww -- wwan
 *
 * type of names:
 *   o<index>                   -- on-board device index number
 *   s<slot>[f<function>]       -- hotplug slot index number
 *   x<MAC>                     -- MAC address
 *   p<bus>s<slot>[f<function>] -- PCI geographical location
 *
 * All multi-function devices will carry the [f<function>] number in the
 * device name, including the function 0 device.
 *
 * examples:
 *   ID_NET_NAME_ONBOARD=eno1
 *   ID_NET_NAME_SLOT=ens1
 *   ID_NET_NAME_SLOT=ens2f0
 *   ID_NET_NAME_SLOT=ens2f1
 *   ID_NET_NAME_MAC=enxf0def180d479
 *   ID_NET_NAME_PATH=enp0s25
 *   ID_NET_NAME_PATH=enp19s3f0
 *   ID_NET_NAME_PATH=enp19s3f1
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/pci_regs.h>

#include "udev.h"

/* retrieve on-board index number and label from firmware */
static int dev_pci_onboard(struct udev_device *dev, struct udev_device *parent, const char *prefix, bool test) {
        const char *index;
        int idx;
        const char *label;
        char s[16];
        int err;

        /* ACPI _DSM  -- device specific method for naming a PCI or PCI Express device */
        index = udev_device_get_sysattr_value(parent, "acpi_index");
        /* SMBIOS type 41 -- Onboard Devices Extended Information */
        if (!index)
                index = udev_device_get_sysattr_value(parent, "index");
        if (!index)
                return -ENOENT;
        idx = strtoul(index, NULL, 0);
        if (idx <= 0)
                return -EINVAL;
        snprintf(s, sizeof(s), "%so%d", prefix, idx);
        err = udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", s);
        if (err < 0)
                return err;

        label = udev_device_get_sysattr_value(parent, "label");
        if (label) {
                err = udev_builtin_add_property(dev, test, "ID_NET_LABEL_ONBOARD", label);
                if (err < 0)
                        return err;
        }
        return 0;
}

/* read the 256 bytes PCI configuration space to check the multi-function bit */
static bool is_pci_singlefunction(struct udev_device *dev) {
        char filename[256];
        FILE *f;
        char config[256];
        bool single = false;

        snprintf(filename, sizeof(filename), "%s/config", udev_device_get_syspath(dev));
        f = fopen(filename, "re");
        if (!f)
                goto out;
        if (fread(&config, sizeof(config), 1, f) != 1)
                goto out;

        /* bit 0-6 header type, bit 7 multi/single function device */
        if ((config[PCI_HEADER_TYPE] & 0x80) == 0)
                single = true;
out:
        fclose(f);
        return single;
}

static int dev_pci_slot(struct udev_device *dev, struct udev_device *parent, const char *prefix, bool test) {
        struct udev *udev = udev_device_get_udev(dev);
        unsigned int bus;
        unsigned int slot;
        unsigned int func;
        struct udev_device *pci = NULL;
        char slots[256];
        DIR *dir;
        struct dirent *dent;
        char str[256];
        int hotplug_slot = 0;
        int err = 0;

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        if (sscanf(udev_device_get_sysname(parent), "0000:%x:%x.%d", &bus, &slot, &func) != 3)
                return -ENOENT;
        if (func == 0 && is_pci_singlefunction(parent))
                snprintf(str, sizeof(str), "%sp%ds%d", prefix, bus, slot);
        else
                snprintf(str, sizeof(str), "%sp%ds%df%d", prefix, bus, slot, func);
        err = udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        if (err < 0)
                return err;

        /* ACPI _SUN  -- slot user number */
        pci = udev_device_new_from_subsystem_sysname(udev, "subsystem", "pci");
        if (!pci) {
                err = -ENOENT;
                goto out;
        }
        snprintf(slots, sizeof(slots), "%s/slots", udev_device_get_syspath(pci));
        dir = opendir(slots);
        if (!dir) {
                err = -errno;
                goto out;
        }

        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                int i;
                char *rest;
                char *address;

                if (dent->d_name[0] == '.')
                        continue;
                i = strtol(dent->d_name, &rest, 10);
                if (rest[0] != '\0')
                        continue;
                if (i < 1)
                        continue;
                snprintf(str, sizeof(str), "%s/%s/address", slots, dent->d_name);
                if (read_one_line_file(str, &address) >= 0) {
                        /* match slot address with device by stripping the function */
                        if (strncmp(address, udev_device_get_sysname(parent), strlen(address)) == 0)
                                hotplug_slot = i;
                        free(address);
                }

                if (hotplug_slot > 0)
                        break;
        }
        closedir(dir);

        if (hotplug_slot > 0) {
                if (func == 0 && is_pci_singlefunction(parent))
                        snprintf(str, sizeof(str), "%ss%d", prefix, hotplug_slot);
                else
                        snprintf(str, sizeof(str), "%ss%df%d", prefix, hotplug_slot, func);
                err = udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
        }
out:
        udev_device_unref(pci);
        return err;
}

static int dev_pci(struct udev_device *dev, const char *prefix, bool test) {
        struct udev_device *parent;

        /* skip other buses than direct PCI parents */
        parent = udev_device_get_parent(dev);
        if (!parent || !streq("pci", udev_device_get_subsystem(parent)))
                return -ENOENT;

        dev_pci_onboard(dev, parent, prefix, test);
        dev_pci_slot(dev, parent, prefix, test);
        return 0;
}

static int dev_mac(struct udev_device *dev, const char *prefix, bool test) {
        const char *s;
        unsigned int i;
        unsigned int a1, a2, a3, a4, a5, a6;
        char str[16];

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

        /*
         * IEEE Organizationally Unique Identifier vendor string
         * skip commonly misused 00:00:00 (Xerox) prefix
         */
        if (a1 + a2 + a3 > 0) {
                snprintf(str, sizeof(str), "OUI:%02X%02X%02X%02X%02X%02X", a1, a2, a3, a4, a5, a6);
                udev_builtin_hwdb_lookup(dev, str, test);
        }

        snprintf(str, sizeof(str), "%sx%02x%02x%02x%02x%02x%02x", prefix, a1, a2, a3, a4, a5, a6);
        return udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);
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
