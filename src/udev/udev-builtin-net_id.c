/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Predictable network interface device names based on:
 *  - firmware/bios-provided index numbers for on-board devices
 *  - firmware-provided pci-express hotplug slot index number
 *  - physical/geographical location of the hardware
 *  - the interface's MAC address
 *
 * https://systemd.io/PREDICTABLE_INTERFACE_NAMES
 *
 * When the code here is changed, man/systemd.net-naming-scheme.xml must be updated too.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/pci_regs.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glyph-util.h"
#include "netif-naming-scheme.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "udev-builtin.h"

#define ONBOARD_14BIT_INDEX_MAX ((1U << 14) - 1)
#define ONBOARD_16BIT_INDEX_MAX ((1U << 16) - 1)

/* skip intermediate virtio devices */
static sd_device *skip_virtio(sd_device *dev) {
        /* there can only ever be one virtio bus per parent device, so we can
         * safely ignore any virtio buses. see
         * http://lists.linuxfoundation.org/pipermail/virtualization/2015-August/030331.html */
        while (dev) {
                const char *subsystem;

                if (sd_device_get_subsystem(dev, &subsystem) < 0)
                        break;

                if (!streq(subsystem, "virtio"))
                        break;

                if (sd_device_get_parent(dev, &dev) < 0)
                        return NULL;
        }

        return dev;
}

static int get_virtfn_info(sd_device *pcidev, sd_device **ret_physfn_pcidev, char **ret_suffix) {
        _cleanup_(sd_device_unrefp) sd_device *physfn_pcidev = NULL;
        const char *syspath, *name;
        sd_device *child;
        int r;

        assert(pcidev);
        assert(ret_physfn_pcidev);
        assert(ret_suffix);

        r = sd_device_get_syspath(pcidev, &syspath);
        if (r < 0)
                return r;

        /* Get physical function's pci device. */
        r = sd_device_new_child(&physfn_pcidev, pcidev, "physfn");
        if (r < 0)
                return r;

        /* Find the virtual function number by finding the right virtfn link. */
        FOREACH_DEVICE_CHILD_WITH_SUFFIX(physfn_pcidev, child, name) {
                const char *n, *s;

                /* Only accepts e.g. virtfn0, virtfn1, and so on. */
                n = startswith(name, "virtfn");
                if (isempty(n) || !in_charset(n, DIGITS))
                        continue;

                if (sd_device_get_syspath(child, &s) < 0)
                        continue;

                if (streq(s, syspath)) {
                        char *suffix;

                        suffix = strjoin("v", n);
                        if (!suffix)
                                return -ENOMEM;

                        *ret_physfn_pcidev = sd_device_ref(child);
                        *ret_suffix = suffix;
                        return 0;
                }
        }

        return -ENOENT;
}

static int get_dev_port(sd_device *dev, bool fallback_to_dev_id, unsigned *ret) {
        unsigned v, iftype;
        int r;

        assert(dev);
        assert(ret);

        /* kernel provided port index for multiple ports on a single PCI function */

        if (fallback_to_dev_id) {
                r = device_get_sysattr_unsigned(dev, "type", &iftype);
                if (r < 0)
                        return r;
                fallback_to_dev_id = (iftype == ARPHRD_INFINIBAND);
        }

        r = device_get_sysattr_unsigned(dev, "dev_port", &v);
        if (r < 0)
                return r;
        if (r > 0 || !fallback_to_dev_id) {
                *ret = v;
                return r;
        }

        /* With older kernels IP-over-InfiniBand network interfaces sometimes erroneously provide the port
         * number in the 'dev_id' sysfs attribute instead of 'dev_port', which thus stays initialized as 0. */
        return device_get_sysattr_unsigned(dev, "dev_id", ret);
}

static bool is_valid_onboard_index(unsigned long idx) {
        /* Some BIOSes report rubbish indexes that are excessively high (2^24-1 is an index VMware likes to
         * report for example). Let's define a cut-off where we don't consider the index reliable anymore. We
         * pick some arbitrary cut-off, which is somewhere beyond the realistic number of physical network
         * interface a system might have. Ideally the kernel would already filter this crap for us, but it
         * doesn't currently. The initial cut-off value (2^14-1) was too conservative for s390 PCI which
         * allows for index values up 2^16-1 which is now enabled with the NAMING_16BIT_INDEX naming flag. */
        return idx <= (naming_scheme_has(NAMING_16BIT_INDEX) ? ONBOARD_16BIT_INDEX_MAX : ONBOARD_14BIT_INDEX_MAX);
}

static int names_pci_onboard(sd_device *dev, sd_device *pci_dev, const char *prefix, const char *suffix, bool test) {
        const char *label, *phys_port_name = NULL;
        unsigned idx, dev_port;
        size_t l;
        char *s;
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* retrieve on-board index number and label from firmware */

        /* ACPI _DSM — device specific method for naming a PCI or PCI Express device */
        r = device_get_sysattr_unsigned(pci_dev, "acpi_index", &idx);
        if (r < 0)
                /* SMBIOS type 41 — Onboard Devices Extended Information */
                r = device_get_sysattr_unsigned(pci_dev, "index", &idx);
        if (r < 0)
                return r;

        if (idx == 0 && !naming_scheme_has(NAMING_ZERO_ACPI_INDEX))
                return log_device_debug_errno(pci_dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Naming scheme does not allow onboard index==0.");
        if (!is_valid_onboard_index(idx))
                return log_device_debug_errno(pci_dev, SYNTHETIC_ERRNO(ENOENT),
                                              "Not a valid onboard index: %u", idx);

        r = get_dev_port(dev, /* fallback_to_dev_id = */ false, &dev_port);
        if (r < 0)
                return r;

        (void) sd_device_get_sysattr_value(dev, "phys_port_name", &phys_port_name);

        char str[ALTIFNAMSIZ];
        s = str;
        l = sizeof(str);
        l = strpcpyf(&s, l, "%so%u", prefix, idx);
        if (!isempty(phys_port_name))
                /* kernel provided front panel port name for multiple port PCI device */
                l = strpcpyf(&s, l, "n%s", phys_port_name);
        else if (dev_port > 0)
                l = strpcpyf(&s, l, "d%u", dev_port);
        if (!isempty(suffix))
                l = strpcpy(&s, l, suffix);
        if (l != 0)
                udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);

        log_device_debug(dev, "Onboard index identifier: index=%u phys_port=%s dev_port=%u virtfn=%s %s %s",
                         idx, strempty(phys_port_name), dev_port, strna(startswith(suffix, "v")),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));

        if (!isempty(suffix))
                return 0;

        r = sd_device_get_sysattr_value(pci_dev, "label", &label);
        if (r < 0)
                return r;

        if (snprintf_ok(str, sizeof str, "%s%s",
                        naming_scheme_has(NAMING_LABEL_NOPREFIX) ? "" : prefix,
                        label))
                udev_builtin_add_property(dev, test, "ID_NET_LABEL_ONBOARD", str);

        log_device_debug(dev, "Onboard label from PCI device: %s", label);
        return 0;
}

/* read the 256 bytes PCI configuration space to check the multi-function bit */
static int is_pci_multifunction(sd_device *dev) {
        _cleanup_free_ uint8_t *config = NULL;
        const char *filename, *syspath;
        size_t len;
        int r;

        assert(dev);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        filename = strjoina(syspath, "/config");
        r = read_virtual_file(filename, PCI_HEADER_TYPE + 1, (char **) &config, &len);
        if (r < 0)
                return r;
        if (len < PCI_HEADER_TYPE + 1)
                return -EINVAL;

#ifndef PCI_HEADER_TYPE_MULTIFUNC
#define PCI_HEADER_TYPE_MULTIFUNC 0x80
#endif

        /* bit 0-6 header type, bit 7 multi/single function device */
        return config[PCI_HEADER_TYPE] & PCI_HEADER_TYPE_MULTIFUNC;
}

static bool is_pci_ari_enabled(sd_device *dev) {
        assert(dev);

        return device_get_sysattr_bool(dev, "ari_enabled") > 0;
}

static bool is_pci_bridge(sd_device *dev) {
        const char *v, *p;

        assert(dev);

        if (sd_device_get_sysattr_value(dev, "modalias", &v) < 0)
                return false;

        if (!startswith(v, "pci:"))
                return false;

        p = strrchr(v, 's');
        if (!p)
                return false;
        if (p[1] != 'c')
                return false;

        /* PCI device subclass 04 corresponds to PCI bridge */
        bool b = strneq(p + 2, "04", 2);
        if (b)
                log_device_debug(dev, "Device is a PCI bridge.");
        return b;
}

static int parse_hotplug_slot_from_function_id(sd_device *dev, int slots_dirfd, uint32_t *ret) {
        uint64_t function_id;
        char filename[NAME_MAX+1];
        const char *attr;
        int r;

        /* The <sysname>/function_id attribute is unique to the s390 PCI driver. If present, we know that the
         * slot's directory name for this device is /sys/bus/pci/slots/XXXXXXXX/ where XXXXXXXX is the fixed
         * length 8 hexadecimal character string representation of function_id. Therefore we can short cut
         * here and just check for the existence of the slot directory. As this directory has to exist, we're
         * emitting a debug message for the unlikely case it's not found. Note that the domain part doesn't
         * belong to the slot name here because there's a 1-to-1 relationship between PCI function and its
         * hotplug slot. See https://docs.kernel.org/s390/pci.html for more details. */

        assert(dev);
        assert(slots_dirfd >= 0);
        assert(ret);

        if (!naming_scheme_has(NAMING_SLOT_FUNCTION_ID)) {
                *ret = 0;
                return 0;
        }

        if (sd_device_get_sysattr_value(dev, "function_id", &attr) < 0) {
                *ret = 0;
                return 0;
        }

        r = safe_atou64(attr, &function_id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse function_id, ignoring: %s", attr);

        if (function_id <= 0 || function_id > UINT32_MAX)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid function id (0x%"PRIx64"), ignoring.",
                                              function_id);

        if (!snprintf_ok(filename, sizeof(filename), "%08"PRIx64, function_id))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENAMETOOLONG),
                                              "PCI slot path is too long, ignoring.");

        if (faccessat(slots_dirfd, filename, F_OK, 0) < 0)
                return log_device_debug_errno(dev, errno, "Cannot access %s under pci slots, ignoring: %m", filename);

        *ret = (uint32_t) function_id;
        return 1; /* Found. We shoud ignore domain part. */
}

static int pci_get_hotplug_slot(sd_device *dev, uint32_t *ret) {
        _cleanup_(sd_device_unrefp) sd_device *pci = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        int r;

        assert(dev);
        assert(ret);

        /* ACPI _SUN — slot user number */
        r = sd_device_new_from_subsystem_sysname(&pci, "subsystem", "pci");
        if (r < 0)
                return log_debug_errno(r, "Failed to create sd_device object for pci subsystem: %m");

        r = device_opendir(pci, "slots", &dir);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Cannot open 'slots' subdirectory: %m");

        for (sd_device *slot_dev = dev; slot_dev; ) {
                const char *sysname;
                uint32_t slot = 0;  /* avoid false maybe-uninitialized warning */

                r = parse_hotplug_slot_from_function_id(slot_dev, dirfd(dir), &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = slot;
                        return 1; /* domain should be ignored. */
                }

                r = sd_device_get_sysname(slot_dev, &sysname);
                if (r < 0)
                        return log_device_debug_errno(slot_dev, r, "Failed to get sysname: %m");

                FOREACH_DIRENT_ALL(de, dir, break) {
                        _cleanup_free_ char *path = NULL;
                        const char *address;

                        if (dot_or_dot_dot(de->d_name))
                                continue;

                        if (de->d_type != DT_DIR)
                                continue;

                        r = safe_atou32(de->d_name, &slot);
                        if (r < 0 || slot <= 0)
                                continue;

                        path = path_join("slots", de->d_name, "address");
                        if (!path)
                                return -ENOMEM;

                        if (sd_device_get_sysattr_value(pci, path, &address) < 0)
                                continue;

                        /* match slot address with device by stripping the function */
                        if (!startswith(sysname, address))
                                continue;

                        /* We found the match between PCI device and slot. However, we won't use the slot
                         * index if the device is a PCI bridge, because it can have other child devices that
                         * will try to claim the same index and that would create name collision. */
                        if (naming_scheme_has(NAMING_BRIDGE_NO_SLOT) && is_pci_bridge(slot_dev)) {
                                if (naming_scheme_has(NAMING_BRIDGE_MULTIFUNCTION_SLOT) && is_pci_multifunction(dev) <= 0)
                                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ESTALE),
                                                                      "Not using slot information because the PCI device associated with "
                                                                      "the hotplug slot is a bridge and the PCI device has a single function.");

                                if (!naming_scheme_has(NAMING_BRIDGE_MULTIFUNCTION_SLOT))
                                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ESTALE),
                                                                      "Not using slot information because the PCI device is a bridge.");
                        }

                        *ret = slot;
                        return 0; /* domain can be still used. */
                }

                if (sd_device_get_parent_with_subsystem_devtype(slot_dev, "pci", NULL, &slot_dev) < 0)
                        break;

                rewinddir(dir);
        }

        return -ENOENT;
}

static int names_pci_slot(sd_device *dev, sd_device *pci_dev, const char *prefix, const char *suffix, bool test) {
        const char *sysname, *phys_port_name = NULL;
        unsigned domain, bus, slot, func, dev_port;
        uint32_t hotplug_slot;
        char str[ALTIFNAMSIZ], *s;
        size_t l;
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* get PCI based path names, we compose only PCI based paths */

        r = sd_device_get_sysname(pci_dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(pci_dev, r, "Failed to get sysname: %m");

        r = sscanf(sysname, "%x:%x:%x.%u", &domain, &bus, &slot, &func);
        log_device_debug(dev, "Parsing slot information from PCI device sysname \"%s\": %s",
                         sysname, r == 4 ? "success" : "failure");
        if (r != 4)
                return -ENOENT;

        if (naming_scheme_has(NAMING_NPAR_ARI) &&
            is_pci_ari_enabled(pci_dev))
                /* ARI devices support up to 256 functions on a single device ("slot"), and interpret the
                 * traditional 5-bit slot and 3-bit function number as a single 8-bit function number,
                 * where the slot makes up the upper 5 bits. */
                func += slot * 8;

        r = get_dev_port(dev, /* fallback_to_dev_id = */ true, &dev_port);
        if (r < 0)
                return r;

        (void) sd_device_get_sysattr_value(dev, "phys_port_name", &phys_port_name);

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        s = str;
        l = strpcpy(&s, sizeof(str), prefix);
        if (domain > 0)
                l = strpcpyf(&s, l, "P%u", domain);
        l = strpcpyf(&s, l, "p%us%u", bus, slot);
        if (func > 0 || is_pci_multifunction(pci_dev) > 0)
                l = strpcpyf(&s, l, "f%u", func);
        if (!isempty(phys_port_name))
                /* kernel provided front panel port name for multi-port PCI device */
                l = strpcpyf(&s, l, "n%s", phys_port_name);
        else if (dev_port > 0)
                l = strpcpyf(&s, l, "d%u", dev_port);
        if (!isempty(suffix))
                l = strpcpy(&s, l, suffix);
        if (l != 0)
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

        log_device_debug(dev, "PCI path identifier: domain=%u bus=%u slot=%u func=%u phys_port=%s dev_port=%u %s %s",
                         domain, bus, slot, func, strempty(phys_port_name), dev_port,
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));

        r = pci_get_hotplug_slot(pci_dev, &hotplug_slot);
        if (r < 0)
                return r;
        if (r > 0)
                domain = 0;

        s = str;
        l = strpcpy(&s, sizeof(str), prefix);
        if (domain > 0)
                l = strpcpyf(&s, l, "P%u", domain);
        l = strpcpyf(&s, l, "s%"PRIu32, hotplug_slot);
        if (func > 0 || is_pci_multifunction(pci_dev) > 0)
                l = strpcpyf(&s, l, "f%u", func);
        if (!isempty(phys_port_name))
                l = strpcpyf(&s, l, "n%s", phys_port_name);
        else if (dev_port > 0)
                l = strpcpyf(&s, l, "d%u", dev_port);
        if (!isempty(suffix))
                l = strpcpy(&s, l, suffix);
        if (l != 0)
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);

        log_device_debug(dev, "Slot identifier: domain=%u slot=%"PRIu32" func=%u phys_port=%s dev_port=%u %s %s",
                         domain, hotplug_slot, func, strempty(phys_port_name), dev_port,
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));

        return 0;
}

static int names_vio(sd_device *dev, const char *prefix, bool test) {
        sd_device *parent;
        unsigned slotid;
        const char *syspath, *subsystem;
        char *s;
        int r;

        assert(dev);
        assert(prefix);

        /* get ibmveth/ibmvnic slot-based names. */

        /* check if our direct parent is a VIO device with no other bus in-between */
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return log_device_debug_errno(dev, r, "sd_device_get_parent() failed: %m");

        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return log_device_debug_errno(parent, r, "sd_device_get_subsystem() failed: %m");
        if (!streq(subsystem, "vio"))
                return -ENOENT;
        log_device_debug(dev, "Parent device is in the vio subsystem.");

        /* The devices' $DEVPATH number is tied to (virtual) hardware (slot id
         * selected in the HMC), thus this provides a reliable naming (e.g.
         * "/devices/vio/30000002/net/eth1"); we ignore the bus number, as
         * there should only ever be one bus, and then remove leading zeros. */
        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_device_debug_errno(dev, r, "sd_device_get_syspath() failed: %m");

        s = path_startswith(syspath, "/sys/devices/vio/");
        if (!s)
                return -EINVAL;

        s = strndupa(s, strspn(s, HEXDIGITS));
        r = safe_atou_full(s, 16, &slotid);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse vio slot from syspath \"%s\": %m", syspath);

        slotid &= 0xffffu; /* drop the bus number */

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sv%u", prefix, slotid))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
        log_device_debug(dev, "Vio slot identifier: slotid=%u %s %s",
                         slotid, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

#define PLATFORM_TEST "/sys/devices/platform/vvvvPPPP"
#define PLATFORM_PATTERN4 "/sys/devices/platform/%4s%4x:%2x/net/eth%u"
#define PLATFORM_PATTERN3 "/sys/devices/platform/%3s%4x:%2x/net/eth%u"

static int names_platform(sd_device *dev, const char *prefix, bool test) {
        sd_device *parent;
        char vendor[5];
        unsigned model, instance, ethid;
        const char *syspath, *pattern, *validchars, *subsystem;
        int r;

        assert(dev);
        assert(prefix);

        /* get ACPI path names for ARM64 platform devices */

        /* check if our direct parent is a platform device with no other bus in-between */
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return log_device_debug_errno(dev, r, "sd_device_get_parent() failed: %m");

        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return log_device_debug_errno(parent, r, "sd_device_get_subsystem() failed: %m");

        if (!streq(subsystem, "platform"))
                 return -ENOENT;
        log_device_debug(dev, "Parent device is in the platform subsystem.");

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_device_debug_errno(dev, r, "sd_device_get_syspath() failed: %m");

        /* syspath is too short, to have a valid ACPI instance */
        if (strlen(syspath) < STRLEN(PLATFORM_TEST) + 1)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Syspath \"%s\" is too short for a valid ACPI instance.",
                                              syspath);

        /* Vendor ID can be either PNP ID (3 chars A-Z) or ACPI ID (4 chars A-Z and numerals) */
        if (syspath[STRLEN(PLATFORM_TEST)] == ':') {
                pattern = PLATFORM_PATTERN4;
                validchars = UPPERCASE_LETTERS DIGITS;
        } else {
                pattern = PLATFORM_PATTERN3;
                validchars = UPPERCASE_LETTERS;
        }

        /* Platform devices are named after ACPI table match, and instance id
         * eg. "/sys/devices/platform/HISI00C2:00");
         * The Vendor (3 or 4 char), followed by hexadecimal model number : instance id. */

        DISABLE_WARNING_FORMAT_NONLITERAL;
        r = sscanf(syspath, pattern, vendor, &model, &instance, &ethid);
        REENABLE_WARNING;
        log_device_debug(dev, "Parsing platform device information from syspath \"%s\": %s",
                         syspath, r == 4 ? "success" : "failure");
        if (r != 4)
                return -EINVAL;

        if (!in_charset(vendor, validchars))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOENT),
                                              "Platform vendor contains invalid characters: %s", vendor);

        ascii_strlower(vendor);

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sa%s%xi%u", prefix, vendor, model, instance))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Platform identifier: vendor=%s model=%x instance=%u %s %s",
                         vendor, model, instance, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int names_devicetree(sd_device *dev, const char *prefix, bool test) {
        _cleanup_(sd_device_unrefp) sd_device *aliases_dev = NULL, *ofnode_dev = NULL, *devicetree_dev = NULL;
        const char *alias, *ofnode_path, *ofnode_syspath, *devicetree_syspath;
        sd_device *parent;
        int r;

        assert(dev);
        assert(prefix);

        if (!naming_scheme_has(NAMING_DEVICETREE_ALIASES))
                return 0;

        /* only ethernet supported for now */
        if (!streq(prefix, "en"))
                return -EOPNOTSUPP;

        /* check if our direct parent has an of_node */
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return r;

        r = sd_device_new_child(&ofnode_dev, parent, "of_node");
        if (r < 0)
                return r;

        r = sd_device_get_syspath(ofnode_dev, &ofnode_syspath);
        if (r < 0)
                return r;

        /* /proc/device-tree should be a symlink to /sys/firmware/devicetree/base. */
        r = sd_device_new_from_path(&devicetree_dev, "/proc/device-tree");
        if (r < 0)
                return r;

        r = sd_device_get_syspath(devicetree_dev, &devicetree_syspath);
        if (r < 0)
                return r;

        /*
         * Example paths:
         * devicetree_syspath = /sys/firmware/devicetree/base
         * ofnode_syspath = /sys/firmware/devicetree/base/soc/ethernet@deadbeef
         * ofnode_path = soc/ethernet@deadbeef
         */
        ofnode_path = path_startswith(ofnode_syspath, devicetree_syspath);
        if (!ofnode_path)
                return -ENOENT;

        /* Get back our leading / to match the contents of the aliases */
        ofnode_path--;
        assert(path_is_absolute(ofnode_path));

        r = sd_device_new_child(&aliases_dev, devicetree_dev, "aliases");
        if (r < 0)
                return r;

        FOREACH_DEVICE_SYSATTR(aliases_dev, alias) {
                const char *alias_path, *alias_index, *conflict;
                unsigned i;

                alias_index = startswith(alias, "ethernet");
                if (!alias_index)
                        continue;

                if (sd_device_get_sysattr_value(aliases_dev, alias, &alias_path) < 0)
                        continue;

                if (!path_equal(ofnode_path, alias_path))
                        continue;

                /* If there's no index, we default to 0... */
                if (isempty(alias_index)) {
                        i = 0;
                        conflict = "ethernet0";
                } else {
                        r = safe_atou(alias_index, &i);
                        if (r < 0)
                                return log_device_debug_errno(dev, r,
                                                "Could not get index of alias %s: %m", alias);
                        conflict = "ethernet";
                }

                /* ...but make sure we don't have an alias conflict */
                if (i == 0 && sd_device_get_sysattr_value(aliases_dev, conflict, NULL) >= 0)
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EEXIST),
                                        "Ethernet alias conflict: ethernet and ethernet0 both exist");

                char str[ALTIFNAMSIZ];
                if (snprintf_ok(str, sizeof str, "%sd%u", prefix, i))
                        udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);
                log_device_debug(dev, "devicetree identifier: alias_index=%u %s \"%s\"",
                                 i, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
                return 0;
        }

        return -ENOENT;
}

static int names_pci(sd_device *dev, const char *prefix, bool test) {
        _cleanup_(sd_device_unrefp) sd_device *physfn_pcidev = NULL;
        _cleanup_free_ char *virtfn_suffix = NULL;
        sd_device *parent;
        const char *subsystem;
        int r;

        assert(dev);
        assert(prefix);

        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return r;

        /* skip virtio subsystem if present */
        parent = skip_virtio(parent);
        if (!parent)
                return -ENOENT;

        /* check if our direct parent is a PCI device with no other bus in-between */
        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return r;

        if (!streq(subsystem, "pci"))
                return -EINVAL;

        /* If this is an SR-IOV virtual device, get base name using physical device and add virtfn suffix. */
        if (naming_scheme_has(NAMING_SR_IOV_V))
                (void) get_virtfn_info(parent, &physfn_pcidev, &virtfn_suffix);

        (void) names_pci_onboard(dev, physfn_pcidev ?: parent, prefix, virtfn_suffix, test);
        (void) names_pci_slot(dev, physfn_pcidev ?: parent, prefix, virtfn_suffix, test);
        return 0;
}

static int names_usb(sd_device *dev, const char *prefix, bool test) {
        sd_device *usbdev, *pcidev;
        char str[ALTIFNAMSIZ], *name, *ports, *config, *interf, *s;
        const char *sysname;
        size_t l;
        int r;

        assert(dev);
        assert(prefix);

        r = sd_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface", &usbdev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not find usb parent device: %m");

        r = sd_device_get_parent_with_subsystem_devtype(dev, "pci", NULL, &pcidev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not find pci parent device: %m");

        r = sd_device_get_sysname(usbdev, &sysname);
        if (r < 0)
                return log_device_debug_errno(usbdev, r, "sd_device_get_sysname() failed: %m");

        /* get USB port number chain, configuration, interface */
        name = strdupa(sysname);
        s = strchr(name, '-');
        if (!s)
                return log_device_debug_errno(usbdev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have '-' in the expected place.", sysname);
        ports = s+1;

        s = strchr(ports, ':');
        if (!s)
                return log_device_debug_errno(usbdev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have ':' in the expected place.", sysname);
        s[0] = '\0';
        config = s+1;

        s = strchr(config, '.');
        if (!s)
                return log_device_debug_errno(usbdev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have '.' in the expected place.", sysname);
        s[0] = '\0';
        interf = s+1;

        /* prefix every port number in the chain with "u" */
        s = ports;
        while ((s = strchr(s, '.')))
                s[0] = 'u';

        s = str;
        l = strpcpyl(&s, sizeof(str), "u", ports, NULL);

        /* append USB config number, suppress the common config == 1 */
        if (!streq(config, "1"))
                l = strpcpyl(&s, l, "c", config, NULL);

        /* append USB interface number, suppress the interface == 0 */
        if (!streq(interf, "0"))
                l = strpcpyl(&s, l, "i", interf, NULL);
        if (l == 0)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENAMETOOLONG),
                                              "Generated USB name would be too long.");

        log_device_debug(dev, "USB name identifier: ports=%.*s config=%s interface=%s %s %s",
                         (int) strlen(ports), sysname + (ports - name), config, interf,
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str);

        return names_pci_slot(dev, pcidev, prefix, str, test);
}

static int names_bcma(sd_device *dev, const char *prefix, bool test) {
        sd_device *bcmadev, *pcidev;
        unsigned core;
        const char *sysname;
        char str[ALTIFNAMSIZ];
        int r;

        assert(dev);
        assert(prefix);

        r = sd_device_get_parent_with_subsystem_devtype(dev, "bcma", NULL, &bcmadev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not get bcma parent device: %m");

        r = sd_device_get_parent_with_subsystem_devtype(dev, "pci", NULL, &pcidev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not get pci parent device: %m");

        r = sd_device_get_sysname(bcmadev, &sysname);
        if (r < 0)
                return log_device_debug_errno(bcmadev, r, "sd_device_get_sysname() failed: %m");

        /* bus num:core num */
        r = sscanf(sysname, "bcma%*u:%u", &core);
        log_device_debug(dev, "Parsing bcma device information from sysname \"%s\": %s",
                         sysname, r == 1 ? "success" : "failure");
        if (r != 1)
                return -EINVAL;
        /* suppress the common core == 0 */
        if (core > 0)
                xsprintf(str, "b%u", core);
        else
                str[0] = '\0';

        log_device_debug(dev, "BCMA core identifier: core=%u %s \"%s\"",
                         core, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str);

        return names_pci_slot(dev, pcidev, prefix, str, test);
}

static int names_ccw(sd_device *dev, const char *prefix, bool test) {
        sd_device *cdev;
        const char *bus_id, *subsys;
        size_t bus_id_start, bus_id_len;
        int r;

        assert(dev);
        assert(prefix);

        /* get path names for Linux on System z network devices */

        /* Retrieve the associated CCW device */
        r = sd_device_get_parent(dev, &cdev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "sd_device_get_parent() failed: %m");

        /* skip virtio subsystem if present */
        cdev = skip_virtio(cdev);
        if (!cdev)
                return -ENOENT;

        r = sd_device_get_subsystem(cdev, &subsys);
        if (r < 0)
                return log_device_debug_errno(cdev, r, "sd_device_get_subsystem() failed: %m");

        /* Network devices are either single or grouped CCW devices */
        if (!STR_IN_SET(subsys, "ccwgroup", "ccw"))
                return -ENOENT;
        log_device_debug(dev, "Device is CCW.");

        /* Retrieve bus-ID of the CCW device.  The bus-ID uniquely
         * identifies the network device on the Linux on System z channel
         * subsystem.  Note that the bus-ID contains lowercase characters.
         */
        r = sd_device_get_sysname(cdev, &bus_id);
        if (r < 0)
                return log_device_debug_errno(cdev, r, "Failed to get sysname: %m");

        /* Check the length of the bus-ID. Rely on the fact that the kernel provides a correct bus-ID;
         * alternatively, improve this check and parse and verify each bus-ID part...
         */
        bus_id_len = strlen(bus_id);
        if (!IN_SET(bus_id_len, 8, 9))
                return log_device_debug_errno(cdev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid bus_id: %s", bus_id);

        /* Strip leading zeros from the bus id for aesthetic purposes. This
         * keeps the ccw names stable, yet much shorter in general case of
         * bus_id 0.0.0600 -> 600. This is similar to e.g. how PCI domain is
         * not prepended when it is zero. Preserve the last 0 for 0.0.0000.
         */
        bus_id_start = strspn(bus_id, ".0");
        bus_id += bus_id_start < bus_id_len ? bus_id_start : bus_id_len - 1;

        /* Use the CCW bus-ID as network device name */
        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sc%s", prefix, bus_id))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "CCW identifier: ccw_busid=%s %s \"%s\"",
                         bus_id, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
static int ieee_oui(sd_device *dev, const struct hw_addr_data *hw_addr, bool test) {
        char str[32];

        assert(dev);
        assert(hw_addr);

        if (hw_addr->length != 6)
                return -EOPNOTSUPP;

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (hw_addr->bytes[0] == 0 &&
            hw_addr->bytes[1] == 0 &&
            hw_addr->bytes[2] == 0)
                return -EINVAL;

        xsprintf(str, "OUI:%02X%02X%02X%02X%02X%02X",
                 hw_addr->bytes[0],
                 hw_addr->bytes[1],
                 hw_addr->bytes[2],
                 hw_addr->bytes[3],
                 hw_addr->bytes[4],
                 hw_addr->bytes[5]);

        return udev_builtin_hwdb_lookup(dev, NULL, str, NULL, test);
}

static int names_mac(sd_device *dev, const char *prefix, bool test) {
        unsigned iftype, assign_type;
        struct hw_addr_data hw_addr;
        const char *s;
        int r;

        assert(dev);
        assert(prefix);

        r = device_get_sysattr_unsigned(dev, "type", &iftype);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read 'type' attribute: %m");

        /* The persistent part of a hardware address of an InfiniBand NIC is 8 bytes long. We cannot
         * fit this much in an iface name.
         * TODO: but it can be used as alternative names?? */
        if (iftype == ARPHRD_INFINIBAND)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                              "Not generating MAC name for infiniband device.");

        /* check for NET_ADDR_PERM, skip random MAC addresses */
        r = device_get_sysattr_unsigned(dev, "addr_assign_type", &assign_type);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read/parse addr_assign_type: %m");

        if (assign_type != NET_ADDR_PERM)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "addr_assign_type=%u, MAC address is not permanent.", assign_type);

        r = sd_device_get_sysattr_value(dev, "address", &s);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read 'address' attribute: %m");

        r = parse_hw_addr(s, &hw_addr);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse 'address' attribute: %m");

        if (hw_addr.length != 6)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                              "Not generating MAC name for device with MAC address of length %zu.",
                                              hw_addr.length);

        char str[ALTIFNAMSIZ];
        xsprintf(str, "%sx%s", prefix, HW_ADDR_TO_STR_FULL(&hw_addr, HW_ADDR_TO_STRING_NO_COLON));
        udev_builtin_add_property(dev, test, "ID_NET_NAME_MAC", str);
        log_device_debug(dev, "MAC address identifier: hw_addr=%s %s %s",
                         HW_ADDR_TO_STR(&hw_addr),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));

        (void) ieee_oui(dev, &hw_addr, test);
        return 0;
}

static int names_netdevsim(sd_device *dev, const char *prefix, bool test) {
        sd_device *netdevsimdev;
        const char *sysnum, *phys_port_name;
        unsigned addr;
        int r;

        assert(dev);
        assert(prefix);

        /* get netdevsim path names */

        if (!naming_scheme_has(NAMING_NETDEVSIM))
                return 0;

        r = sd_device_get_parent_with_subsystem_devtype(dev, "netdevsim", NULL, &netdevsimdev);
        if (r < 0)
                return r;

        r = sd_device_get_sysnum(netdevsimdev, &sysnum);
        if (r < 0)
                return r;

        r = safe_atou(sysnum, &addr);
        if (r < 0)
                return r;

        r = sd_device_get_sysattr_value(dev, "phys_port_name", &phys_port_name);
        if (r < 0)
                return r;
        if (isempty(phys_port_name))
                return -EOPNOTSUPP;

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%si%un%s", prefix, addr, phys_port_name))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Netdevsim identifier: address=%u, port_name=%s %s %s",
                         addr, phys_port_name, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int names_xen(sd_device *dev, const char *prefix, bool test) {
        sd_device *parent;
        unsigned id;
        const char *syspath, *subsystem, *p, *p2;
        int r;

        assert(dev);
        assert(prefix);

        /* get xen vif "slot" based names. */

        if (!naming_scheme_has(NAMING_XEN_VIF))
                return 0;

        /* check if our direct parent is a Xen VIF device with no other bus in-between */
        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return r;

        /* Do an exact-match on subsystem "xen". This will miss on "xen-backend" on
         * purpose as the VIFs on the backend (dom0) have their own naming scheme
         * which we don't want to affect
         */
        r = sd_device_get_subsystem(parent, &subsystem);
        if (r < 0)
                return r;
        if (!streq(subsystem, "xen"))
                return -ENOENT;

        /* Use the vif-n name to extract "n" */
        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        p = path_startswith(syspath, "/sys/devices/");
        if (!p)
                return -ENOENT;
        p = startswith(p, "vif-");
        if (!p)
                return -ENOENT;
        p2 = strchr(p, '/');
        if (!p2)
                return -ENOENT;
        p = strndupa_safe(p, p2 - p);
        if (!p)
                return -ENOENT;
        r = safe_atou_full(p, SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO |
                           SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10, &id);
        if (r < 0)
                return r;

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sX%u", prefix, id))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
        log_device_debug(dev, "Xen identifier: id=%u %s %s",
                         id, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int get_ifname_prefix(sd_device *dev, const char **ret) {
        unsigned iftype;
        int r;

        assert(dev);
        assert(ret);

        r = device_get_sysattr_unsigned(dev, "type", &iftype);
        if (r < 0)
                return r;

        /* handle only ARPHRD_ETHER, ARPHRD_SLIP and ARPHRD_INFINIBAND devices */
        switch (iftype) {
        case ARPHRD_ETHER: {
                const char *s = NULL;

                r = sd_device_get_devtype(dev, &s);
                if (r < 0 && r != -ENOENT)
                        return r;

                if (streq_ptr(s, "wlan"))
                        *ret = "wl";
                else if (streq_ptr(s, "wwan"))
                        *ret = "ww";
                else
                        *ret = "en";
                return 0;
        }
        case ARPHRD_INFINIBAND:
                if (!naming_scheme_has(NAMING_INFINIBAND))
                        return -EOPNOTSUPP;

                *ret = "ib";
                return 0;

        case ARPHRD_SLIP:
                *ret = "sl";
                return 0;

        default:
                return -EOPNOTSUPP;
        }
}

static int builtin_net_id(sd_device *dev, sd_netlink **rtnl, int argc, char *argv[], bool test) {
        const char *prefix;
        int ifindex, iflink, r;

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r < 0)
                return r;

        r = device_get_sysattr_int(dev, "iflink", &iflink);
        if (r < 0)
                return r;

        /* skip stacked devices, like VLANs, ... */
        if (ifindex != iflink)
                return 0;

        r = get_ifname_prefix(dev, &prefix);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to determine prefix for network interface naming, ignoring: %m");
                return 0;
        }

        udev_builtin_add_property(dev, test, "ID_NET_NAMING_SCHEME", naming_scheme()->name);

        (void) names_mac(dev, prefix, test);
        (void) names_devicetree(dev, prefix, test);
        (void) names_ccw(dev, prefix, test);
        (void) names_vio(dev, prefix, test);
        (void) names_platform(dev, prefix, test);
        (void) names_netdevsim(dev, prefix, test);
        (void) names_xen(dev, prefix, test);
        (void) names_pci(dev, prefix, test);
        (void) names_usb(dev, prefix, test);
        (void) names_bcma(dev, prefix, test);

        return 0;
}

static int builtin_net_id_init(void) {
        /* Load naming scheme here to suppress log messages in workers. */
        naming_scheme();
        return 0;
}

const UdevBuiltin udev_builtin_net_id = {
        .name = "net_id",
        .cmd = builtin_net_id,
        .init = builtin_net_id_init,
        .help = "Network device properties",
};
