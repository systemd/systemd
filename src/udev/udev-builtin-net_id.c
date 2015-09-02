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
 * Predictable network interface device names based on:
 *  - firmware/bios-provided index numbers for on-board devices
 *  - firmware-provided pci-express hotplug slot index number
 *  - physical/geographical location of the hardware
 *  - the interface's MAC address
 *
 * http://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames
 *
 * Two character prefixes based on the type of interface:
 *   en -- ethernet
 *   sl -- serial line IP (slip)
 *   wl -- wlan
 *   ww -- wwan
 *
 * Type of names:
 *   b<number>                             -- BCMA bus core number
 *   ccw<name>                             -- CCW bus group name
 *   o<index>[d<dev_port>]                 -- on-board device index number
 *   s<slot>[f<function>][d<dev_port>]     -- hotplug slot index number
 *   x<MAC>                                -- MAC address
 *   [P<domain>]p<bus>s<slot>[f<function>][d<dev_port>]
 *                                         -- PCI geographical location
 *   [P<domain>]p<bus>s<slot>[f<function>][u<port>][..][c<config>][i<interface>]
 *                                         -- USB port number chain
 *
 * All multi-function PCI devices will carry the [f<function>] number in the
 * device name, including the function 0 device.
 *
 * When using PCI geography, The PCI domain is only prepended when it is not 0.
 *
 * For USB devices the full chain of port numbers of hubs is composed. If the
 * name gets longer than the maximum number of 15 characters, the name is not
 * exported.
 * The usual USB configuration == 1 and interface == 0 values are suppressed.
 *
 * PCI ethernet card with firmware index "1":
 *   ID_NET_NAME_ONBOARD=eno1
 *   ID_NET_NAME_ONBOARD_LABEL=Ethernet Port 1
 *
 * PCI ethernet card in hotplug slot with firmware index number:
 *   /sys/devices/pci0000:00/0000:00:1c.3/0000:05:00.0/net/ens1
 *   ID_NET_NAME_MAC=enx000000000466
 *   ID_NET_NAME_PATH=enp5s0
 *   ID_NET_NAME_SLOT=ens1
 *
 * PCI ethernet multi-function card with 2 ports:
 *   /sys/devices/pci0000:00/0000:00:1c.0/0000:02:00.0/net/enp2s0f0
 *   ID_NET_NAME_MAC=enx78e7d1ea46da
 *   ID_NET_NAME_PATH=enp2s0f0
 *   /sys/devices/pci0000:00/0000:00:1c.0/0000:02:00.1/net/enp2s0f1
 *   ID_NET_NAME_MAC=enx78e7d1ea46dc
 *   ID_NET_NAME_PATH=enp2s0f1
 *
 * PCI wlan card:
 *   /sys/devices/pci0000:00/0000:00:1c.1/0000:03:00.0/net/wlp3s0
 *   ID_NET_NAME_MAC=wlx0024d7e31130
 *   ID_NET_NAME_PATH=wlp3s0
 *
 * USB built-in 3G modem:
 *   /sys/devices/pci0000:00/0000:00:1d.0/usb2/2-1/2-1.4/2-1.4:1.6/net/wwp0s29u1u4i6
 *   ID_NET_NAME_MAC=wwx028037ec0200
 *   ID_NET_NAME_PATH=wwp0s29u1u4i6
 *
 * USB Android phone:
 *   /sys/devices/pci0000:00/0000:00:1d.0/usb2/2-1/2-1.2/2-1.2:1.0/net/enp0s29u1u2
 *   ID_NET_NAME_MAC=enxd626b3450fb5
 *   ID_NET_NAME_PATH=enp0s29u1u2
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/pci_regs.h>

#include "udev.h"
#include "fileio.h"

enum netname_type{
        NET_UNDEF,
        NET_PCI,
        NET_USB,
        NET_BCMA,
        NET_VIRTIO,
        NET_CCWGROUP,
};

struct netnames {
        enum netname_type type;

        uint8_t mac[6];
        bool mac_valid;

        struct udev_device *pcidev;
        char pci_slot[IFNAMSIZ];
        char pci_path[IFNAMSIZ];
        char pci_onboard[IFNAMSIZ];
        const char *pci_onboard_label;

        char usb_ports[IFNAMSIZ];
        char bcma_core[IFNAMSIZ];
        char ccw_group[IFNAMSIZ];
};

/* retrieve on-board index number and label from firmware */
static int dev_pci_onboard(struct udev_device *dev, struct netnames *names) {
        unsigned dev_port = 0;
        size_t l;
        char *s;
        const char *attr;
        int idx;

        /* ACPI _DSM  -- device specific method for naming a PCI or PCI Express device */
        attr = udev_device_get_sysattr_value(names->pcidev, "acpi_index");
        /* SMBIOS type 41 -- Onboard Devices Extended Information */
        if (!attr)
                attr = udev_device_get_sysattr_value(names->pcidev, "index");
        if (!attr)
                return -ENOENT;

        idx = strtoul(attr, NULL, 0);
        if (idx <= 0)
                return -EINVAL;

        /* kernel provided port index for multiple ports on a single PCI function */
        attr = udev_device_get_sysattr_value(dev, "dev_port");
        if (attr)
                dev_port = strtol(attr, NULL, 10);

        s = names->pci_onboard;
        l = sizeof(names->pci_onboard);
        l = strpcpyf(&s, l, "o%d", idx);
        if (dev_port > 0)
                l = strpcpyf(&s, l, "d%d", dev_port);
        if (l == 0)
                names->pci_onboard[0] = '\0';

        names->pci_onboard_label = udev_device_get_sysattr_value(names->pcidev, "label");

        return 0;
}

/* read the 256 bytes PCI configuration space to check the multi-function bit */
static bool is_pci_multifunction(struct udev_device *dev) {
        _cleanup_close_ int fd = -1;
        const char *filename;
        uint8_t config[64];

        filename = strjoina(udev_device_get_syspath(dev), "/config");
        fd = open(filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return false;
        if (read(fd, &config, sizeof(config)) != sizeof(config))
                return false;

        /* bit 0-6 header type, bit 7 multi/single function device */
        if ((config[PCI_HEADER_TYPE] & 0x80) != 0)
                return true;

        return false;
}

static int dev_pci_slot(struct udev_device *dev, struct netnames *names) {
        struct udev *udev = udev_device_get_udev(names->pcidev);
        unsigned domain, bus, slot, func, dev_port = 0;
        size_t l;
        char *s;
        const char *attr;
        struct udev_device *pci = NULL;
        char slots[256], str[256];
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *dent;
        int hotplug_slot = 0, err = 0;

        if (sscanf(udev_device_get_sysname(names->pcidev), "%x:%x:%x.%u", &domain, &bus, &slot, &func) != 4)
                return -ENOENT;

        /* kernel provided port index for multiple ports on a single PCI function */
        attr = udev_device_get_sysattr_value(dev, "dev_port");
        if (attr)
                dev_port = strtol(attr, NULL, 10);

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        s = names->pci_path;
        l = sizeof(names->pci_path);
        if (domain > 0)
                l = strpcpyf(&s, l, "P%u", domain);
        l = strpcpyf(&s, l, "p%us%u", bus, slot);
        if (func > 0 || is_pci_multifunction(names->pcidev))
                l = strpcpyf(&s, l, "f%u", func);
        if (dev_port > 0)
                l = strpcpyf(&s, l, "d%u", dev_port);
        if (l == 0)
                names->pci_path[0] = '\0';

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
                        if (strneq(address, udev_device_get_sysname(names->pcidev), strlen(address)))
                                hotplug_slot = i;
                        free(address);
                }

                if (hotplug_slot > 0)
                        break;
        }

        if (hotplug_slot > 0) {
                s = names->pci_slot;
                l = sizeof(names->pci_slot);
                if (domain > 0)
                        l = strpcpyf(&s, l, "P%d", domain);
                l = strpcpyf(&s, l, "s%d", hotplug_slot);
                if (func > 0 || is_pci_multifunction(names->pcidev))
                        l = strpcpyf(&s, l, "f%d", func);
                if (dev_port > 0)
                        l = strpcpyf(&s, l, "d%d", dev_port);
                if (l == 0)
                        names->pci_slot[0] = '\0';
        }
out:
        udev_device_unref(pci);
        return err;
}

static int names_pci(struct udev_device *dev, struct netnames *names) {
        struct udev_device *parent;

        assert(dev);
        assert(names);

        parent = udev_device_get_parent(dev);

        /* there can only ever be one virtio bus per parent device, so we can
           safely ignore any virtio buses. see
           <http://lists.linuxfoundation.org/pipermail/virtualization/2015-August/030331.html> */
        while (parent && streq_ptr("virtio", udev_device_get_subsystem(parent)))
                parent = udev_device_get_parent(parent);

        if (!parent)
                return -ENOENT;

        /* check if our direct parent is a PCI device with no other bus in-between */
        if (streq_ptr("pci", udev_device_get_subsystem(parent))) {
                names->type = NET_PCI;
                names->pcidev = parent;
        } else {
                names->pcidev = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
                if (!names->pcidev)
                        return -ENOENT;
        }
        dev_pci_onboard(dev, names);
        dev_pci_slot(dev, names);
        return 0;
}

static int names_usb(struct udev_device *dev, struct netnames *names) {
        struct udev_device *usbdev;
        char name[256];
        char *ports;
        char *config;
        char *interf;
        size_t l;
        char *s;

        assert(dev);
        assert(names);

        usbdev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface");
        if (!usbdev)
                return -ENOENT;

        /* get USB port number chain, configuration, interface */
        strscpy(name, sizeof(name), udev_device_get_sysname(usbdev));
        s = strchr(name, '-');
        if (!s)
                return -EINVAL;
        ports = s+1;

        s = strchr(ports, ':');
        if (!s)
                return -EINVAL;
        s[0] = '\0';
        config = s+1;

        s = strchr(config, '.');
        if (!s)
                return -EINVAL;
        s[0] = '\0';
        interf = s+1;

        /* prefix every port number in the chain with "u" */
        s = ports;
        while ((s = strchr(s, '.')))
                s[0] = 'u';
        s = names->usb_ports;
        l = strpcpyl(&s, sizeof(names->usb_ports), "u", ports, NULL);

        /* append USB config number, suppress the common config == 1 */
        if (!streq(config, "1"))
                l = strpcpyl(&s, sizeof(names->usb_ports), "c", config, NULL);

        /* append USB interface number, suppress the interface == 0 */
        if (!streq(interf, "0"))
                l = strpcpyl(&s, sizeof(names->usb_ports), "i", interf, NULL);
        if (l == 0)
                return -ENAMETOOLONG;

        names->type = NET_USB;
        return 0;
}

static int names_bcma(struct udev_device *dev, struct netnames *names) {
        struct udev_device *bcmadev;
        unsigned int core;

        assert(dev);
        assert(names);

        bcmadev = udev_device_get_parent_with_subsystem_devtype(dev, "bcma", NULL);
        if (!bcmadev)
                return -ENOENT;

        /* bus num:core num */
        if (sscanf(udev_device_get_sysname(bcmadev), "bcma%*u:%u", &core) != 1)
                return -EINVAL;
        /* suppress the common core == 0 */
        if (core > 0)
                snprintf(names->bcma_core, sizeof(names->bcma_core), "b%u", core);

        names->type = NET_BCMA;
        return 0;
}

static int names_ccw(struct  udev_device *dev, struct netnames *names) {
        struct udev_device *cdev;
        const char *bus_id;
        size_t bus_id_len;
        int rc;

        assert(dev);
        assert(names);

        /* Retrieve the associated CCW device */
        cdev = udev_device_get_parent(dev);
        if (!cdev)
                return -ENOENT;

        /* Network devices are always grouped CCW devices */
        if (!streq_ptr("ccwgroup", udev_device_get_subsystem(cdev)))
                return -ENOENT;

        /* Retrieve bus-ID of the grouped CCW device.  The bus-ID uniquely
         * identifies the network device on the Linux on System z channel
         * subsystem.  Note that the bus-ID contains lowercase characters.
         */
        bus_id = udev_device_get_sysname(cdev);
        if (!bus_id)
                return -ENOENT;

        /* Check the length of the bus-ID.  Rely on that the kernel provides
         * a correct bus-ID; alternatively, improve this check and parse and
         * verify each bus-ID part...
         */
        bus_id_len = strlen(bus_id);
        if (!bus_id_len || bus_id_len < 8 || bus_id_len > 9)
                return -EINVAL;

        /* Store the CCW bus-ID for use as network device name */
        rc = snprintf(names->ccw_group, sizeof(names->ccw_group), "ccw%s", bus_id);
        if (rc >= 0 && rc < (int)sizeof(names->ccw_group))
                names->type = NET_CCWGROUP;
        return 0;
}

static int names_mac(struct udev_device *dev, struct netnames *names) {
        const char *s;
        unsigned int i;
        unsigned int a1, a2, a3, a4, a5, a6;

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

        names->mac[0] = a1;
        names->mac[1] = a2;
        names->mac[2] = a3;
        names->mac[3] = a4;
        names->mac[4] = a5;
        names->mac[5] = a6;
        names->mac_valid = true;
        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
static int ieee_oui(struct udev_device *dev, struct netnames *names, bool test) {
        char str[32];

        if (!names->mac_valid)
                return -ENOENT;
        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (memcmp(names->mac, "\0\0\0", 3) == 0)
                return -EINVAL;
        snprintf(str, sizeof(str), "OUI:%02X%02X%02X%02X%02X%02X",
                 names->mac[0], names->mac[1], names->mac[2],
                 names->mac[3], names->mac[4], names->mac[5]);
        udev_builtin_hwdb_lookup(dev, NULL, str, NULL, test);
        return 0;
}

static int builtin_net_id(struct udev_device *dev, int argc, char *argv[], bool test) {
        const char *s;
        const char *p;
        unsigned int i;
        const char *devtype;
        const char *prefix = "en";
        struct netnames names = {};
        int err;

        /* handle only ARPHRD_ETHER and ARPHRD_SLIP devices */
        s = udev_device_get_sysattr_value(dev, "type");
        if (!s)
                return EXIT_FAILURE;
        i = strtoul(s, NULL, 0);
        switch (i) {
        case ARPHRD_ETHER:
                prefix = "en";
                break;
        case ARPHRD_SLIP:
                prefix = "sl";
                break;
        default:
                return 0;
        }

        /* skip stacked devices, like VLANs, ... */
        s = udev_device_get_sysattr_value(dev, "ifindex");
        if (!s)
                return EXIT_FAILURE;
        p = udev_device_get_sysattr_value(dev, "iflink");
        if (!p)
                return EXIT_FAILURE;
        if (!streq(s, p))
                return 0;

        devtype = udev_device_get_devtype(dev);
        if (devtype) {
                if (streq("wlan", devtype))
                        prefix = "wl";
                else if (streq("wwan", devtype))
                        prefix = "ww";
        }

        err = names_mac(dev, &names);
        if (err >= 0 && names.mac_valid) {
                char str[IFNAMSIZ];

                snprintf(str, sizeof(str), "%sx%02x%02x%02x%02x%02x%02x", prefix,
                         names.mac[0], names.mac[1], names.mac[2],
                         names.mac[3], names.mac[4], names.mac[5]);
                udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);

                ieee_oui(dev, &names, test);
        }

        /* get path names for Linux on System z network devices */
        err = names_ccw(dev, &names);
        if (err >= 0 && names.type == NET_CCWGROUP) {
                char str[IFNAMSIZ];

                if (snprintf(str, sizeof(str), "%s%s", prefix, names.ccw_group) < (int)sizeof(str))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
                goto out;
        }

        /* get PCI based path names, we compose only PCI based paths */
        err = names_pci(dev, &names);
        if (err < 0)
                goto out;

        /* plain PCI device */
        if (names.type == NET_PCI) {
                char str[IFNAMSIZ];

                if (names.pci_onboard[0])
                        if (snprintf(str, sizeof(str), "%s%s", prefix, names.pci_onboard) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);

                if (names.pci_onboard_label)
                        if (snprintf(str, sizeof(str), "%s%s", prefix, names.pci_onboard_label) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_LABEL_ONBOARD", str);

                if (names.pci_path[0])
                        if (snprintf(str, sizeof(str), "%s%s", prefix, names.pci_path) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0])
                        if (snprintf(str, sizeof(str), "%s%s", prefix, names.pci_slot) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }

        /* USB device */
        err = names_usb(dev, &names);
        if (err >= 0 && names.type == NET_USB) {
                char str[IFNAMSIZ];

                if (names.pci_path[0])
                        if (snprintf(str, sizeof(str), "%s%s%s", prefix, names.pci_path, names.usb_ports) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0])
                        if (snprintf(str, sizeof(str), "%s%s%s", prefix, names.pci_slot, names.usb_ports) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }

        /* Broadcom bus */
        err = names_bcma(dev, &names);
        if (err >= 0 && names.type == NET_BCMA) {
                char str[IFNAMSIZ];

                if (names.pci_path[0])
                        if (snprintf(str, sizeof(str), "%s%s%s", prefix, names.pci_path, names.bcma_core) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0])
                        if (snprintf(str, sizeof(str), "%s%s%s", prefix, names.pci_slot, names.bcma_core) < (int)sizeof(str))
                                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }
out:
        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .help = "Network device properties",
};
