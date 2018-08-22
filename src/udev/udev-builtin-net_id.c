/* SPDX-License-Identifier: LGPL-2.1+ */

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
 *   en — Ethernet
 *   sl — serial line IP (slip)
 *   wl — wlan
 *   ww — wwan
 *
 * Type of names:
 *   b<number>                             — BCMA bus core number
 *   c<bus_id>                             — bus id of a grouped CCW or CCW device,
 *                                           with all leading zeros stripped [s390]
 *   o<index>[n<phys_port_name>|d<dev_port>]
 *                                         — on-board device index number
 *   s<slot>[f<function>][n<phys_port_name>|d<dev_port>]
 *                                         — hotplug slot index number
 *   x<MAC>                                — MAC address
 *   [P<domain>]p<bus>s<slot>[f<function>][n<phys_port_name>|d<dev_port>]
 *                                         — PCI geographical location
 *   [P<domain>]p<bus>s<slot>[f<function>][u<port>][..][c<config>][i<interface>]
 *                                         — USB port number chain
 *   v<slot>                               - VIO slot number (IBM PowerVM)
 *   a<vendor><model>i<instance>           — Platform bus ACPI instance id
 *
 * All multi-function PCI devices will carry the [f<function>] number in the
 * device name, including the function 0 device.
 *
 * SR-IOV virtual devices are named based on the name of the parent interface,
 * with a suffix of "v<N>", where <N> is the virtual device number.
 *
 * When using PCI geography, The PCI domain is only prepended when it is not 0.
 *
 * For USB devices the full chain of port numbers of hubs is composed. If the
 * name gets longer than the maximum number of 15 characters, the name is not
 * exported.
 * The usual USB configuration == 1 and interface == 0 values are suppressed.
 *
 * PCI Ethernet card with firmware index "1":
 *   ID_NET_NAME_ONBOARD=eno1
 *   ID_NET_NAME_ONBOARD_LABEL=Ethernet Port 1
 *
 * PCI Ethernet card in hotplug slot with firmware index number:
 *   /sys/devices/pci0000:00/0000:00:1c.3/0000:05:00.0/net/ens1
 *   ID_NET_NAME_MAC=enx000000000466
 *   ID_NET_NAME_PATH=enp5s0
 *   ID_NET_NAME_SLOT=ens1
 *
 * PCI Ethernet multi-function card with 2 ports:
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
 *
 * s390 grouped CCW interface:
 *  /sys/devices/css0/0.0.0007/0.0.f5f0/group_device/net/encf5f0
 *  ID_NET_NAME_MAC=enx026d3c00000a
 *  ID_NET_NAME_PATH=encf5f0
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/pci_regs.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev.h"

#define ONBOARD_INDEX_MAX (16*1024-1)

enum netname_type{
        NET_UNDEF,
        NET_PCI,
        NET_USB,
        NET_BCMA,
        NET_VIRTIO,
        NET_CCW,
        NET_VIO,
        NET_PLATFORM,
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
        char ccw_busid[IFNAMSIZ];
        char vio_slot[IFNAMSIZ];
        char platform_path[IFNAMSIZ];
};

struct virtfn_info {
        struct udev_device *physfn_pcidev;
        char suffix[IFNAMSIZ];
};

/* skip intermediate virtio devices */
static struct udev_device *skip_virtio(struct udev_device *dev) {
        struct udev_device *parent = dev;

        /* there can only ever be one virtio bus per parent device, so we can
           safely ignore any virtio buses. see
           <http://lists.linuxfoundation.org/pipermail/virtualization/2015-August/030331.html> */
        while (parent && streq_ptr("virtio", udev_device_get_subsystem(parent)))
                parent = udev_device_get_parent(parent);
        return parent;
}

static int get_virtfn_info(struct udev_device *dev, struct netnames *names, struct virtfn_info *vf_info) {
        struct udev *udev;
        const char *physfn_link_file;
        _cleanup_free_ char *physfn_pci_syspath = NULL;
        _cleanup_free_ char *virtfn_pci_syspath = NULL;
        struct dirent *dent;
        _cleanup_closedir_ DIR *dir = NULL;
        struct virtfn_info vf_info_local = {};
        int r;

        udev = udev_device_get_udev(names->pcidev);
        if (!udev)
                return -ENOENT;
        /* Check if this is a virtual function. */
        physfn_link_file = strjoina(udev_device_get_syspath(names->pcidev), "/physfn");
        r = chase_symlinks(physfn_link_file, NULL, 0, &physfn_pci_syspath);
        if (r < 0)
                return r;

        /* Get physical function's pci device. */
        vf_info_local.physfn_pcidev = udev_device_new_from_syspath(udev, physfn_pci_syspath);
        if (!vf_info_local.physfn_pcidev)
                return -ENOENT;

        /* Find the virtual function number by finding the right virtfn link. */
        dir = opendir(physfn_pci_syspath);
        if (!dir) {
                r = -errno;
                goto out_unref;
        }
        FOREACH_DIRENT_ALL(dent, dir, break) {
                _cleanup_free_ char *virtfn_link_file = NULL;
                if (!startswith(dent->d_name, "virtfn"))
                        continue;
                virtfn_link_file = strjoin(physfn_pci_syspath, "/", dent->d_name);
                if (!virtfn_link_file) {
                        r = -ENOMEM;
                        goto out_unref;
                }
                if (chase_symlinks(virtfn_link_file, NULL, 0, &virtfn_pci_syspath) < 0)
                        continue;
                if (streq(udev_device_get_syspath(names->pcidev), virtfn_pci_syspath)) {
                        if (!snprintf_ok(vf_info_local.suffix, sizeof(vf_info_local.suffix), "v%s", &dent->d_name[6])) {
                                r = -ENOENT;
                                goto out_unref;
                        }
                        break;
                }
        }
        if (isempty(vf_info_local.suffix)) {
                r = -ENOENT;
                goto out_unref;
        }
        *vf_info = vf_info_local;
        return 0;

out_unref:
        udev_device_unref(vf_info_local.physfn_pcidev);
        return r;
}

/* retrieve on-board index number and label from firmware */
static int dev_pci_onboard(struct udev_device *dev, struct netnames *names) {
        unsigned dev_port = 0;
        size_t l;
        char *s;
        const char *attr, *port_name;
        int idx;

        /* ACPI _DSM  — device specific method for naming a PCI or PCI Express device */
        attr = udev_device_get_sysattr_value(names->pcidev, "acpi_index");
        /* SMBIOS type 41 — Onboard Devices Extended Information */
        if (!attr)
                attr = udev_device_get_sysattr_value(names->pcidev, "index");
        if (!attr)
                return -ENOENT;

        idx = strtoul(attr, NULL, 0);
        if (idx <= 0)
                return -EINVAL;

        /* Some BIOSes report rubbish indexes that are excessively high (2^24-1 is an index VMware likes to report for
         * example). Let's define a cut-off where we don't consider the index reliable anymore. We pick some arbitrary
         * cut-off, which is somewhere beyond the realistic number of physical network interface a system might
         * have. Ideally the kernel would already filter his crap for us, but it doesn't currently. */
        if (idx > ONBOARD_INDEX_MAX)
                return -ENOENT;

        /* kernel provided port index for multiple ports on a single PCI function */
        attr = udev_device_get_sysattr_value(dev, "dev_port");
        if (attr)
                dev_port = strtol(attr, NULL, 10);

        /* kernel provided front panel port name for multiple port PCI device */
        port_name = udev_device_get_sysattr_value(dev, "phys_port_name");

        s = names->pci_onboard;
        l = sizeof(names->pci_onboard);
        l = strpcpyf(&s, l, "o%d", idx);
        if (port_name)
                l = strpcpyf(&s, l, "n%s", port_name);
        else if (dev_port > 0)
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

static bool is_pci_ari_enabled(struct udev_device *dev) {
        return streq_ptr(udev_device_get_sysattr_value(dev, "ari_enabled"), "1");
}

static int dev_pci_slot(struct udev_device *dev, struct netnames *names) {
        struct udev *udev = udev_device_get_udev(names->pcidev);
        unsigned domain, bus, slot, func, dev_port = 0, hotplug_slot = 0;
        size_t l;
        char *s;
        const char *attr, *port_name;
        _cleanup_(udev_device_unrefp) struct udev_device *pci = NULL;
        struct udev_device *hotplug_slot_dev;
        char slots[PATH_MAX];
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *dent;

        if (sscanf(udev_device_get_sysname(names->pcidev), "%x:%x:%x.%u", &domain, &bus, &slot, &func) != 4)
                return -ENOENT;
        if (is_pci_ari_enabled(names->pcidev))
                /* ARI devices support up to 256 functions on a single device ("slot"), and interpret the
                 * traditional 5-bit slot and 3-bit function number as a single 8-bit function number,
                 * where the slot makes up the upper 5 bits. */
                func += slot * 8;

        /* kernel provided port index for multiple ports on a single PCI function */
        attr = udev_device_get_sysattr_value(dev, "dev_port");
        if (attr)
                dev_port = strtol(attr, NULL, 10);

        /* kernel provided front panel port name for multiple port PCI device */
        port_name = udev_device_get_sysattr_value(dev, "phys_port_name");

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        s = names->pci_path;
        l = sizeof(names->pci_path);
        if (domain > 0)
                l = strpcpyf(&s, l, "P%u", domain);
        l = strpcpyf(&s, l, "p%us%u", bus, slot);
        if (func > 0 || is_pci_multifunction(names->pcidev))
                l = strpcpyf(&s, l, "f%u", func);
        if (port_name)
                l = strpcpyf(&s, l, "n%s", port_name);
        else if (dev_port > 0)
                l = strpcpyf(&s, l, "d%u", dev_port);
        if (l == 0)
                names->pci_path[0] = '\0';

        /* ACPI _SUN  — slot user number */
        pci = udev_device_new_from_subsystem_sysname(udev, "subsystem", "pci");
        if (!pci)
                return -ENOENT;

        if (!snprintf_ok(slots, sizeof slots, "%s/slots", udev_device_get_syspath(pci)))
                return -ENAMETOOLONG;

        dir = opendir(slots);
        if (!dir)
                return -errno;

        hotplug_slot_dev = names->pcidev;
        while (hotplug_slot_dev) {
                FOREACH_DIRENT_ALL(dent, dir, break) {
                        unsigned i;
                        int r;
                        char str[PATH_MAX];
                        _cleanup_free_ char *address = NULL;

                        if (dent->d_name[0] == '.')
                                continue;
                        r = safe_atou_full(dent->d_name, 10, &i);
                        if (i < 1 || r < 0)
                                continue;

                        if (snprintf_ok(str, sizeof str, "%s/%s/address", slots, dent->d_name) &&
                            read_one_line_file(str, &address) >= 0)
                                /* match slot address with device by stripping the function */
                                if (startswith(udev_device_get_sysname(hotplug_slot_dev), address))
                                        hotplug_slot = i;

                        if (hotplug_slot > 0)
                                break;
                }
                if (hotplug_slot > 0)
                        break;
                rewinddir(dir);
                hotplug_slot_dev = udev_device_get_parent_with_subsystem_devtype(hotplug_slot_dev, "pci", NULL);
        }

        if (hotplug_slot > 0) {
                s = names->pci_slot;
                l = sizeof(names->pci_slot);
                if (domain > 0)
                        l = strpcpyf(&s, l, "P%d", domain);
                l = strpcpyf(&s, l, "s%d", hotplug_slot);
                if (func > 0 || is_pci_multifunction(names->pcidev))
                        l = strpcpyf(&s, l, "f%d", func);
                if (port_name)
                        l = strpcpyf(&s, l, "n%s", port_name);
                else if (dev_port > 0)
                        l = strpcpyf(&s, l, "d%d", dev_port);
                if (l == 0)
                        names->pci_slot[0] = '\0';
        }

        return 0;
}

static int names_vio(struct udev_device *dev, struct netnames *names) {
        struct udev_device *parent;
        unsigned busid, slotid, ethid;
        const char *syspath;

        /* check if our direct parent is a VIO device with no other bus in-between */
        parent = udev_device_get_parent(dev);
        if (!parent)
                return -ENOENT;

        if (!streq_ptr("vio", udev_device_get_subsystem(parent)))
                 return -ENOENT;

        /* The devices' $DEVPATH number is tied to (virtual) hardware (slot id
         * selected in the HMC), thus this provides a reliable naming (e.g.
         * "/devices/vio/30000002/net/eth1"); we ignore the bus number, as
         * there should only ever be one bus, and then remove leading zeros. */
        syspath = udev_device_get_syspath(dev);

        if (sscanf(syspath, "/sys/devices/vio/%4x%4x/net/eth%u", &busid, &slotid, &ethid) != 3)
                return -EINVAL;

        xsprintf(names->vio_slot, "v%u", slotid);
        names->type = NET_VIO;
        return 0;
}

#define _PLATFORM_TEST "/sys/devices/platform/vvvvPPPP"
#define _PLATFORM_PATTERN4 "/sys/devices/platform/%4s%4x:%2x/net/eth%u"
#define _PLATFORM_PATTERN3 "/sys/devices/platform/%3s%4x:%2x/net/eth%u"

static int names_platform(struct udev_device *dev, struct netnames *names, bool test) {
        struct udev_device *parent;
        char vendor[5];
        unsigned model, instance, ethid;
        const char *syspath, *pattern, *validchars;

        /* check if our direct parent is a platform device with no other bus in-between */
        parent = udev_device_get_parent(dev);
        if (!parent)
                return -ENOENT;

        if (!streq_ptr("platform", udev_device_get_subsystem(parent)))
                 return -ENOENT;

        syspath = udev_device_get_syspath(dev);

        /* syspath is too short, to have a valid ACPI instance */
        if (strlen(syspath) < sizeof _PLATFORM_TEST)
                return -EINVAL;

        /* Vendor ID can be either PNP ID (3 chars A-Z) or ACPI ID (4 chars A-Z and numerals) */
        if (syspath[sizeof _PLATFORM_TEST - 1] == ':') {
                pattern = _PLATFORM_PATTERN4;
                validchars = UPPERCASE_LETTERS DIGITS;
        } else {
                pattern = _PLATFORM_PATTERN3;
                validchars = UPPERCASE_LETTERS;
        }

        /* Platform devices are named after ACPI table match, and instance id
         * eg. "/sys/devices/platform/HISI00C2:00");
         * The Vendor (3 or 4 char), followed by hexdecimal model number : instance id.
         */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        if (sscanf(syspath, pattern, vendor, &model, &instance, &ethid) != 4)
                return -EINVAL;
#pragma GCC diagnostic pop

        if (!in_charset(vendor, validchars))
                return -ENOENT;

        ascii_strlower(vendor);

        xsprintf(names->platform_path, "a%s%xi%u", vendor, model, instance);
        names->type = NET_PLATFORM;
        return 0;
}

static int names_pci(struct udev_device *dev, struct netnames *names) {
        struct udev_device *parent;
        struct netnames vf_names = {};
        struct virtfn_info vf_info = {};

        assert(dev);
        assert(names);

        parent = udev_device_get_parent(dev);
        /* skip virtio subsystem if present */
        parent = skip_virtio(parent);

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

        if (get_virtfn_info(dev, names, &vf_info) >= 0) {
                /* If this is an SR-IOV virtual device, get base name using physical device and add virtfn suffix. */
                vf_names.pcidev = vf_info.physfn_pcidev;
                dev_pci_onboard(dev, &vf_names);
                dev_pci_slot(dev, &vf_names);
                if (vf_names.pci_onboard[0])
                        if (strlen(vf_names.pci_onboard) + strlen(vf_info.suffix) < sizeof(names->pci_onboard))
                                strscpyl(names->pci_onboard, sizeof(names->pci_onboard),
                                         vf_names.pci_onboard, vf_info.suffix, NULL);
                if (vf_names.pci_slot[0])
                        if (strlen(vf_names.pci_slot) + strlen(vf_info.suffix) < sizeof(names->pci_slot))
                                strscpyl(names->pci_slot, sizeof(names->pci_slot),
                                         vf_names.pci_slot, vf_info.suffix, NULL);
                if (vf_names.pci_path[0])
                        if (strlen(vf_names.pci_path) + strlen(vf_info.suffix) < sizeof(names->pci_path))
                                strscpyl(names->pci_path, sizeof(names->pci_path),
                                         vf_names.pci_path, vf_info.suffix, NULL);
                udev_device_unref(vf_info.physfn_pcidev);
        } else {
                dev_pci_onboard(dev, names);
                dev_pci_slot(dev, names);
        }
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
                xsprintf(names->bcma_core, "b%u", core);

        names->type = NET_BCMA;
        return 0;
}

static int names_ccw(struct  udev_device *dev, struct netnames *names) {
        struct udev_device *cdev;
        const char *bus_id, *subsys;
        size_t bus_id_len;
        size_t bus_id_start;

        assert(dev);
        assert(names);

        /* Retrieve the associated CCW device */
        cdev = udev_device_get_parent(dev);
        /* skip virtio subsystem if present */
        cdev = skip_virtio(cdev);
        if (!cdev)
                return -ENOENT;

        /* Network devices are either single or grouped CCW devices */
        subsys = udev_device_get_subsystem(cdev);
        if (!STRPTR_IN_SET(subsys, "ccwgroup", "ccw"))
                return -ENOENT;

        /* Retrieve bus-ID of the CCW device.  The bus-ID uniquely
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
        if (!IN_SET(bus_id_len, 8, 9))
                return -EINVAL;

        /* Strip leading zeros from the bus id for aesthetic purposes. This
         * keeps the ccw names stable, yet much shorter in general case of
         * bus_id 0.0.0600 -> 600. This is similar to e.g. how PCI domain is
         * not prepended when it is zero. Preserve the last 0 for 0.0.0000.
         */
        bus_id_start = strspn(bus_id, ".0");
        bus_id += bus_id_start < bus_id_len ? bus_id_start : bus_id_len - 1;

        /* Store the CCW bus-ID for use as network device name */
        if (snprintf_ok(names->ccw_busid, sizeof(names->ccw_busid), "c%s", bus_id))
                names->type = NET_CCW;

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
        xsprintf(str, "OUI:%02X%02X%02X%02X%02X%02X", names->mac[0],
                 names->mac[1], names->mac[2], names->mac[3], names->mac[4],
                 names->mac[5]);
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

                xsprintf(str, "%sx%02x%02x%02x%02x%02x%02x", prefix,
                         names.mac[0], names.mac[1], names.mac[2],
                         names.mac[3], names.mac[4], names.mac[5]);
                udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);

                ieee_oui(dev, &names, test);
        }

        /* get path names for Linux on System z network devices */
        err = names_ccw(dev, &names);
        if (err >= 0 && names.type == NET_CCW) {
                char str[IFNAMSIZ];

                if (snprintf_ok(str, sizeof str, "%s%s", prefix, names.ccw_busid))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
                goto out;
        }

        /* get ibmveth/ibmvnic slot-based names. */
        err = names_vio(dev, &names);
        if (err >= 0 && names.type == NET_VIO) {
                char str[IFNAMSIZ];

                if (snprintf_ok(str, sizeof str, "%s%s", prefix, names.vio_slot))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }

        /* get ACPI path names for ARM64 platform devices */
        err = names_platform(dev, &names, test);
        if (err >= 0 && names.type == NET_PLATFORM) {
                char str[IFNAMSIZ];

                if (snprintf_ok(str, sizeof str, "%s%s", prefix, names.platform_path))
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

                if (names.pci_onboard[0] &&
                    snprintf_ok(str, sizeof str, "%s%s", prefix, names.pci_onboard))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);

                if (names.pci_onboard_label &&
                    snprintf_ok(str, sizeof str, "%s%s", prefix, names.pci_onboard_label))
                        udev_builtin_add_property(dev, test, "ID_NET_LABEL_ONBOARD", str);

                if (names.pci_path[0] &&
                    snprintf_ok(str, sizeof str, "%s%s", prefix, names.pci_path))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0] &&
                    snprintf_ok(str, sizeof str, "%s%s", prefix, names.pci_slot))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }

        /* USB device */
        err = names_usb(dev, &names);
        if (err >= 0 && names.type == NET_USB) {
                char str[IFNAMSIZ];

                if (names.pci_path[0] &&
                    snprintf_ok(str, sizeof str, "%s%s%s", prefix, names.pci_path, names.usb_ports))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0] &&
                    snprintf_ok(str, sizeof str, "%s%s%s", prefix, names.pci_slot, names.usb_ports))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
                goto out;
        }

        /* Broadcom bus */
        err = names_bcma(dev, &names);
        if (err >= 0 && names.type == NET_BCMA) {
                char str[IFNAMSIZ];

                if (names.pci_path[0] &&
                    snprintf_ok(str, sizeof str, "%s%s%s", prefix, names.pci_path, names.bcma_core))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

                if (names.pci_slot[0] &&
                    snprintf(str, sizeof str, "%s%s%s", prefix, names.pci_slot, names.bcma_core))
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
