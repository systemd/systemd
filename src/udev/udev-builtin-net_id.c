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
#include "chase.h"
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
static sd_device *device_skip_virtio(sd_device *dev) {
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

static int get_matching_parent(
                sd_device *dev,
                char * const *parent_subsystems,
                bool skip_virtio,
                sd_device **ret) {

        sd_device *parent;
        int r;

        assert(dev);

        r = sd_device_get_parent(dev, &parent);
        if (r < 0)
                return r;

        if (skip_virtio) {
                /* skip virtio subsystem if present */
                parent = device_skip_virtio(parent);
                if (!parent)
                        return -ENODEV;
        }

        if (!strv_isempty(parent_subsystems)) {
                const char *subsystem;

                /* check if our direct parent is in an expected subsystem. */
                r = sd_device_get_subsystem(parent, &subsystem);
                if (r < 0)
                        return r;

                if (!strv_contains(parent_subsystems, subsystem))
                        return -ENODEV;
        }

        if (ret)
                *ret = parent;

        return 0;
}

static int get_first_syspath_component(sd_device *dev, const char *prefix, char **ret) {
        _cleanup_free_ char *buf = NULL;
        const char *syspath, *p, *q;
        int r;

        assert(dev);
        assert(prefix);
        assert(ret);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        p = path_startswith(syspath, prefix);
        if (!p)
                return -EINVAL;

        r = path_find_first_component(&p, /* accept_dot_dot = */ false, &q);
        if (r < 0)
                return r;

        buf = strndup(q, r);
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return r; /* return the length of the string */
}

static int get_virtfn_info(sd_device *pcidev, sd_device **ret_physfn_pcidev, char **ret_suffix) {
        _cleanup_(sd_device_unrefp) sd_device *physfn_pcidev = NULL;
        const char *syspath, *name;
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

                        *ret_physfn_pcidev = sd_device_ref(physfn_pcidev);
                        *ret_suffix = suffix;
                        return 0;
                }
        }

        return -ENOENT;
}

static int get_dev_port(sd_device *dev, bool fallback_to_dev_id, unsigned *ret) {
        unsigned v;
        int r;

        assert(dev);
        assert(ret);

        /* Get kernel provided port index for the case when multiple ports on a single PCI function. */

        r = device_get_sysattr_unsigned_filtered(dev, "dev_port", &v);
        if (r < 0)
                return r;
        if (r > 0) {
                /* Found a positive index. Let's use it. */
                *ret = v;
                return 1; /* positive */
        }
        assert(v == 0);

        /* With older kernels IP-over-InfiniBand network interfaces sometimes erroneously provide the port
         * number in the 'dev_id' sysfs attribute instead of 'dev_port', which thus stays initialized as 0. */

        if (fallback_to_dev_id) {
                unsigned iftype;

                r = device_get_sysattr_unsigned_filtered(dev, "type", &iftype);
                if (r < 0)
                        return r;

                fallback_to_dev_id = (iftype == ARPHRD_INFINIBAND);
        }

        if (fallback_to_dev_id)
                return device_get_sysattr_unsigned_filtered(dev, "dev_id", ret);

        /* Otherwise, return the original index 0. */
        *ret = 0;
        return 0; /* zero */
}

static int get_port_specifier(sd_device *dev, bool fallback_to_dev_id, char **ret) {
        const char *phys_port_name;
        unsigned dev_port;
        char *buf;
        int r;

        assert(dev);
        assert(ret);

        /* First, try to use the kernel provided front panel port name for multiple port PCI device. */
        r = sd_device_get_sysattr_value_filtered(dev, "phys_port_name", &phys_port_name);
        if (r >= 0 && !isempty(phys_port_name)) {
                if (naming_scheme_has(NAMING_SR_IOV_R)) {
                        int vf_id = -1;

                        /* Check if phys_port_name indicates virtual device representor. */
                        (void) sscanf(phys_port_name, "pf%*uvf%d", &vf_id);

                        if (vf_id >= 0) {
                                /* For VF representor append 'r<VF_NUM>'. */
                                if (asprintf(&buf, "r%d", vf_id) < 0)
                                        return log_oom_debug();

                                *ret = buf;
                                return 1;
                        }
                }

                /* Otherwise, use phys_port_name as is. */
                buf = strjoin("n", phys_port_name);
                if (!buf)
                        return log_oom_debug();

                *ret = buf;
                return 1;
        }

        /* Then, try to use the kernel provided port index for the case when multiple ports on a single PCI
         * function. */
        r = get_dev_port(dev, fallback_to_dev_id, &dev_port);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device port index: %m");
        if (r > 0) {
                assert(dev_port > 0);
                if (asprintf(&buf, "d%u", dev_port) < 0)
                        return log_oom_debug();

                *ret = buf;
                return 1;
        }

        *ret = NULL;
        return 0;
}

static bool is_valid_onboard_index(unsigned idx) {
        /* Some BIOSes report rubbish indexes that are excessively high (2^24-1 is an index VMware likes to
         * report for example). Let's define a cut-off where we don't consider the index reliable anymore. We
         * pick some arbitrary cut-off, which is somewhere beyond the realistic number of physical network
         * interface a system might have. Ideally the kernel would already filter this crap for us, but it
         * doesn't currently. The initial cut-off value (2^14-1) was too conservative for s390 PCI which
         * allows for index values up 2^16-1 which is now enabled with the NAMING_16BIT_INDEX naming flag. */
        return idx <= (naming_scheme_has(NAMING_16BIT_INDEX) ? ONBOARD_16BIT_INDEX_MAX : ONBOARD_14BIT_INDEX_MAX);
}

static int pci_get_onboard_index(sd_device *dev, unsigned *ret) {
        unsigned idx;
        int r;

        assert(dev);
        assert(ret);

        /* ACPI _DSM — device specific method for naming a PCI or PCI Express device */
        r = device_get_sysattr_unsigned_filtered(dev, "acpi_index", &idx);
        if (r < 0)
                /* SMBIOS type 41 — Onboard Devices Extended Information */
                r = device_get_sysattr_unsigned_filtered(dev, "index", &idx);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not obtain onboard index: %m");

        if (idx == 0 && !naming_scheme_has(NAMING_ZERO_ACPI_INDEX))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Naming scheme does not allow onboard index==0.");
        if (!is_valid_onboard_index(idx))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOENT),
                                              "Not a valid onboard index: %u", idx);

        *ret = idx;
        return 0;
}

static int names_pci_onboard(sd_device *dev, sd_device *pci_dev, const char *prefix, const char *suffix, bool test) {
        _cleanup_free_ char *port = NULL;
        unsigned idx = 0;  /* avoid false maybe-uninitialized warning */
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        /* retrieve on-board index number from firmware */
        r = pci_get_onboard_index(pci_dev, &idx);
        if (r < 0)
                return r;

        r = get_port_specifier(dev, /* fallback_to_dev_id = */ false, &port);
        if (r < 0)
                return r;

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%so%u%s%s", prefix, idx, strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_ONBOARD", str);

        log_device_debug(dev, "Onboard index identifier: index=%u port=%s %s %s",
                         idx, strna(port),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), empty_to_na(str));

        return 0;
}

static int names_pci_onboard_label(sd_device *dev, sd_device *pci_dev, const char *prefix, bool test) {
        const char *label;
        int r;

        assert(dev);
        assert(prefix);

        /* retrieve on-board label from firmware */
        r = sd_device_get_sysattr_value_filtered(pci_dev, "label", &label);
        if (r < 0)
                return log_device_debug_errno(pci_dev, r, "Failed to get PCI onboard label: %m");

        char str[ALTIFNAMSIZ];
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

        return device_get_sysattr_bool_filtered(dev, "ari_enabled") > 0;
}

static bool is_pci_bridge(sd_device *dev) {
        const char *v, *p;

        assert(dev);

        if (sd_device_get_sysattr_value_filtered(dev, "modalias", &v) < 0)
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

        if (sd_device_get_sysattr_value_filtered(dev, "function_id", &attr) < 0) {
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
        return 1; /* Found. We should ignore domain part. */
}

static int pci_get_hotplug_slot_from_address(
                sd_device *dev,
                sd_device *pci,
                DIR *dir,
                uint32_t *ret) {

        const char *sysname;
        int r;

        assert(dev);
        assert(pci);
        assert(dir);
        assert(ret);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        rewinddir(dir);
        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_free_ char *path = NULL;
                const char *address;
                uint32_t slot;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (de->d_type != DT_DIR)
                        continue;

                r = safe_atou32(de->d_name, &slot);
                if (r < 0 || slot <= 0)
                        continue;

                path = path_join("slots", de->d_name, "address");
                if (!path)
                        return log_oom_debug();

                if (sd_device_get_sysattr_value_filtered(pci, path, &address) < 0)
                        continue;

                /* match slot address with device by stripping the function */
                if (!startswith(sysname, address))
                        continue;

                *ret = slot;
                return 1; /* found */
        }

        *ret = 0;
        return 0; /* not found */
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
                uint32_t slot = 0;  /* avoid false maybe-uninitialized warning */

                r = parse_hotplug_slot_from_function_id(slot_dev, dirfd(dir), &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret = slot;
                        return 1; /* domain should be ignored. */
                }

                r = pci_get_hotplug_slot_from_address(slot_dev, pci, dir, &slot);
                if (r < 0)
                        return r;
                if (r > 0) {
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
        }

        return -ENOENT;
}

static int get_pci_slot_specifiers(
                sd_device *dev,
                char **ret_domain,
                char **ret_bus_and_slot,
                char **ret_func) {

        _cleanup_free_ char *domain_spec = NULL, *bus_and_slot_spec = NULL, *func_spec = NULL;
        unsigned domain, bus, slot, func;
        const char *sysname;
        int r;

        assert(dev);
        assert(ret_domain);
        assert(ret_bus_and_slot);
        assert(ret_func);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        r = sscanf(sysname, "%x:%x:%x.%u", &domain, &bus, &slot, &func);
        if (r != 4)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Failed to parse slot information from PCI device sysname.");

        if (naming_scheme_has(NAMING_NPAR_ARI) &&
            is_pci_ari_enabled(dev))
                /* ARI devices support up to 256 functions on a single device ("slot"), and interpret the
                 * traditional 5-bit slot and 3-bit function number as a single 8-bit function number,
                 * where the slot makes up the upper 5 bits. */
                func += slot * 8;

        if (domain > 0 && asprintf(&domain_spec, "P%u", domain) < 0)
                return log_oom_debug();

        if (asprintf(&bus_and_slot_spec, "p%us%u", bus, slot) < 0)
                return log_oom_debug();

        if ((func > 0 || is_pci_multifunction(dev) > 0) &&
            asprintf(&func_spec, "f%u", func) < 0)
                return log_oom_debug();

        *ret_domain = TAKE_PTR(domain_spec);
        *ret_bus_and_slot = TAKE_PTR(bus_and_slot_spec);
        *ret_func = TAKE_PTR(func_spec);
        return 0;
}

static int names_pci_slot(sd_device *dev, sd_device *pci_dev, const char *prefix, const char *suffix, bool test) {
        _cleanup_free_ char *domain = NULL, *bus_and_slot = NULL, *func = NULL, *port = NULL;
        uint32_t hotplug_slot = 0;  /* avoid false maybe-uninitialized warning */
        char str[ALTIFNAMSIZ];
        int r;

        assert(dev);
        assert(pci_dev);
        assert(prefix);

        r = get_pci_slot_specifiers(pci_dev, &domain, &bus_and_slot, &func);
        if (r < 0)
                return r;

        r = get_port_specifier(dev, /* fallback_to_dev_id = */ true, &port);
        if (r < 0)
                return r;

        /* compose a name based on the raw kernel's PCI bus, slot numbers */
        if (snprintf_ok(str, sizeof str, "%s%s%s%s%s%s",
                        prefix, strempty(domain), bus_and_slot, strempty(func), strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

        log_device_debug(dev, "PCI path identifier: domain=%s bus_and_slot=%s func=%s port=%s %s %s",
                         strna(domain), bus_and_slot, strna(func), strna(port),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), empty_to_na(str));

        r = pci_get_hotplug_slot(pci_dev, &hotplug_slot);
        if (r < 0)
                return r;
        if (r > 0)
                /* If the hotplug slot is found through the function ID, then drop the domain from the name.
                 * See comments in parse_hotplug_slot_from_function_id(). */
                domain = mfree(domain);

        if (snprintf_ok(str, sizeof str, "%s%ss%"PRIu32"%s%s%s",
                        prefix, strempty(domain), hotplug_slot, strempty(func), strempty(port), strempty(suffix)))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);

        log_device_debug(dev, "Slot identifier: domain=%s slot=%"PRIu32" func=%s port=%s %s %s",
                         strna(domain), hotplug_slot, strna(func), strna(port),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), empty_to_na(str));

        return 0;
}

static int names_vio(sd_device *dev, const char *prefix, bool test) {
        _cleanup_free_ char *s = NULL;
        unsigned slotid;
        int r;

        assert(dev);
        assert(prefix);

        /* get ibmveth/ibmvnic slot-based names. */

        /* check if our direct parent is a VIO device with no other bus in-between */
        if (get_matching_parent(dev, STRV_MAKE("vio"), /* skip_virtio = */ false, NULL) < 0)
                return 0;

        log_device_debug(dev, "Parent device is in the vio subsystem.");

        /* The devices' $DEVPATH number is tied to (virtual) hardware (slot id
         * selected in the HMC), thus this provides a reliable naming (e.g.
         * "/devices/vio/30000002/net/eth1"); we ignore the bus number, as
         * there should only ever be one bus, and then remove leading zeros. */
        r = get_first_syspath_component(dev, "/sys/devices/vio/", &s);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get VIO bus ID and slot ID: %m");

        if (r != 8)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "VIO bus ID and slot ID have invalid length: %s", s);

        if (!in_charset(s, HEXDIGITS))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "VIO bus ID and slot ID contain invalid characters: %s", s);

        /* Parse only slot ID (the last 4 hexdigits). */
        r = safe_atou_full(s + 4, 16, &slotid);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse VIO slot from '%s': %m", s);

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sv%u", prefix, slotid))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_SLOT", str);
        log_device_debug(dev, "Vio slot identifier: slotid=%u %s %s",
                         slotid, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int names_platform(sd_device *dev, const char *prefix, bool test) {
        _cleanup_free_ char *p = NULL;
        const char *validchars;
        char *vendor, *model_str, *instance_str;
        unsigned model, instance;
        int r;

        assert(dev);
        assert(prefix);

        /* get ACPI path names for ARM64 platform devices */

        /* check if our direct parent is a platform device with no other bus in-between */
        if (get_matching_parent(dev, STRV_MAKE("platform"), /* skip_virtio = */ false, NULL) < 0)
                return 0;

        log_device_debug(dev, "Parent device is in the platform subsystem.");

        r = get_first_syspath_component(dev, "/sys/devices/platform/", &p);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get platform ID: %m");

        /* Platform devices are named after ACPI table match, and instance id
         * eg. "/sys/devices/platform/HISI00C2:00"
         * The Vendor (3 or 4 char), followed by hexadecimal model number : instance id. */
        if (r == 10 && p[7] == ':') {
                /* 3 char vendor string */
                vendor = strndupa(p, 3);
                model_str = strndupa(p + 3, 4);
                instance_str = strndupa(p + 8, 2);
                validchars = UPPERCASE_LETTERS;
        } else if (r == 11 && p[8] == ':') {
                /* 4 char vendor string */
                vendor = strndupa(p, 4);
                model_str = strndupa(p + 4, 4);
                instance_str = strndupa(p + 9, 2);
                validchars = UPPERCASE_LETTERS DIGITS;
        } else
                return -EOPNOTSUPP;

        if (!in_charset(vendor, validchars))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOENT),
                                              "Platform vendor contains invalid characters: %s", vendor);

        ascii_strlower(vendor);

        r = safe_atou_full(model_str, 16, &model);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse model number \"%s\": %m", model_str);

        r = safe_atou_full(instance_str, 16, &instance);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse instance id \"%s\": %m", instance_str);

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%sa%s%xi%u", prefix, vendor, model, instance))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Platform identifier: vendor=%s model=%x instance=%u %s %s",
                         vendor, model, instance, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int names_devicetree(sd_device *dev, const char *prefix, bool test) {
        _cleanup_(sd_device_unrefp) sd_device *aliases_dev = NULL, *ofnode_dev = NULL, *devicetree_dev = NULL;
        const char *ofnode_path, *ofnode_syspath, *devicetree_syspath;
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
                return log_device_debug_errno(dev, r, "Failed to get parent device: %m");

        r = sd_device_new_child(&ofnode_dev, parent, "of_node");
        if (r < 0)
                return log_device_debug_errno(parent, r, "Failed to get 'of_node' child device: %m");

        r = sd_device_get_syspath(ofnode_dev, &ofnode_syspath);
        if (r < 0)
                return log_device_debug_errno(ofnode_dev, r, "Failed to get syspath: %m");

        /* /proc/device-tree should be a symlink to /sys/firmware/devicetree/base. */
        r = sd_device_new_from_path(&devicetree_dev, "/proc/device-tree");
        if (r < 0)
                return log_debug_errno(r, "Failed to create sd-device object from '/proc/device-tree': %m");

        r = sd_device_get_syspath(devicetree_dev, &devicetree_syspath);
        if (r < 0)
                return log_device_debug_errno(devicetree_dev, r, "Failed to get syspath: %m");

        /*
         * Example paths:
         * devicetree_syspath = /sys/firmware/devicetree/base
         * ofnode_syspath = /sys/firmware/devicetree/base/soc/ethernet@deadbeef
         * ofnode_path = soc/ethernet@deadbeef
         */
        ofnode_path = path_startswith(ofnode_syspath, devicetree_syspath);
        if (!ofnode_path)
                return log_device_debug_errno(ofnode_dev, SYNTHETIC_ERRNO(EINVAL),
                                              "The device '%s' is not a child device of '%s': %m",
                                              ofnode_syspath, devicetree_syspath);

        /* Get back our leading / to match the contents of the aliases */
        ofnode_path--;
        assert(path_is_absolute(ofnode_path));

        r = sd_device_new_child(&aliases_dev, devicetree_dev, "aliases");
        if (r < 0)
                return log_device_debug_errno(devicetree_dev, r,
                                              "Failed to get 'aliases' child device: %m");

        FOREACH_DEVICE_SYSATTR(aliases_dev, alias) {
                const char *alias_path, *alias_index, *conflict;
                unsigned i;

                alias_index = startswith(alias, "ethernet");
                if (!alias_index)
                        continue;

                if (sd_device_get_sysattr_value_filtered(aliases_dev, alias, &alias_path) < 0)
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
                if (i == 0 && sd_device_get_sysattr_value_filtered(aliases_dev, conflict, NULL) >= 0)
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

        assert(dev);
        assert(prefix);

        /* check if our direct parent is a PCI device with no other bus in-between */
        if (get_matching_parent(dev, STRV_MAKE("pci"), /* skip_virtio = */ true, &parent) < 0)
                return 0;

        /* If this is an SR-IOV virtual device, get base name using physical device and add virtfn suffix. */
        if (naming_scheme_has(NAMING_SR_IOV_V) &&
            get_virtfn_info(parent, &physfn_pcidev, &virtfn_suffix) >= 0)
                parent = physfn_pcidev;
        else
                (void) names_pci_onboard_label(dev, parent, prefix, test);

        (void) names_pci_onboard(dev, parent, prefix, virtfn_suffix, test);
        (void) names_pci_slot(dev, parent, prefix, virtfn_suffix, test);
        return 0;
}

static int get_usb_specifier(sd_device *dev, char **ret) {
        char *ports, *config, *interf, *s, *buf;
        const char *sysname;
        int r;

        assert(dev);
        assert(ret);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        /* get USB port number chain, configuration, interface */
        s = strchr(sysname, '-');
        if (!s)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have '-' in the expected place.", sysname);

        ports = strdupa_safe(s + 1);
        s = strchr(ports, ':');
        if (!s)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have ':' in the expected place.", sysname);

        *s = '\0';
        config = s + 1;
        s = strchr(config, '.');
        if (!s)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "sysname \"%s\" does not have '.' in the expected place.", sysname);

        *s = '\0';
        interf = s + 1;

        /* prefix every port number in the chain with "u" */
        string_replace_char(ports, '.', 'u');

        /* suppress the common config == 1 */
        if (streq(config, "1"))
                config = NULL;

        /* suppress the interface == 0 */
        if (streq(interf, "0"))
                interf = NULL;

        buf = strjoin("u", ports,
                      config ? "c" : "", strempty(config),
                      interf ? "i" : "", strempty(interf));
        if (!buf)
                return log_oom_debug();

        log_device_debug(dev, "USB name identifier: ports=%s config=%s interface=%s %s %s",
                         ports, strna(config), strna(interf),
                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), buf);

        *ret = buf;
        return 0;
}

static int names_usb(sd_device *dev, const char *prefix, bool test) {
        _cleanup_free_ char *suffix = NULL;
        sd_device *usbdev, *pcidev;
        int r;

        assert(dev);
        assert(prefix);

        /* USB device */

        r = sd_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface", &usbdev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not find usb parent device: %m");

        r = get_usb_specifier(usbdev, &suffix);
        if (r < 0)
                return r;

        /* If the USB bus is on PCI bus, then suffix the USB specifier to the name based on the PCI bus. */
        r = sd_device_get_parent_with_subsystem_devtype(usbdev, "pci", NULL, &pcidev);
        if (r >= 0)
                return names_pci_slot(dev, pcidev, prefix, suffix, test);

        if (r != -ENOENT || !naming_scheme_has(NAMING_USB_HOST))
                return log_device_debug_errno(usbdev, r, "Failed to get parent PCI bus: %m");

        /* Otherwise, e.g. on-chip asics that have USB ports, use the USB specifier as is. */
        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%s%s", prefix, suffix))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);

        return 0;
}

static int get_bcma_specifier(sd_device *dev, char **ret) {
        const char *sysname;
        char *buf = NULL;
        unsigned core;
        int r;

        assert(dev);
        assert(ret);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get sysname: %m");

        /* bus num:core num */
        r = sscanf(sysname, "bcma%*u:%u", &core);
        if (r != 1)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Failed to parse bcma device information.");

        /* suppress the common core == 0 */
        if (core > 0 && asprintf(&buf, "b%u", core) < 0)
                return log_oom_debug();

        log_device_debug(dev, "BCMA core identifier: core=%u %s \"%s\"",
                         core, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), strna(buf));

        *ret = buf;
        return 0;
}

static int names_bcma(sd_device *dev, const char *prefix, bool test) {
        _cleanup_free_ char *suffix = NULL;
        sd_device *bcmadev, *pcidev;
        int r;

        assert(dev);
        assert(prefix);

        r = sd_device_get_parent_with_subsystem_devtype(dev, "bcma", NULL, &bcmadev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not get bcma parent device: %m");

        r = sd_device_get_parent_with_subsystem_devtype(bcmadev, "pci", NULL, &pcidev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Could not get pci parent device: %m");

        r = get_bcma_specifier(bcmadev, &suffix);
        if (r < 0)
                return r;

        return names_pci_slot(dev, pcidev, prefix, suffix, test);
}

static int names_ccw(sd_device *dev, const char *prefix, bool test) {
        sd_device *cdev;
        const char *bus_id;
        size_t bus_id_start, bus_id_len;
        int r;

        assert(dev);
        assert(prefix);

        /* get path names for Linux on System z network devices */

        if (get_matching_parent(dev, STRV_MAKE("ccwgroup", "ccw"), /* skip_virtio = */ true, &cdev) < 0)
                return 0;

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
                return log_device_debug_errno(cdev, SYNTHETIC_ERRNO(EINVAL), "Invalid bus_id: %s", bus_id);

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

        r = device_get_sysattr_unsigned_filtered(dev, "type", &iftype);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read 'type' attribute: %m");

        /* The persistent part of a hardware address of an InfiniBand NIC is 8 bytes long. We cannot
         * fit this much in an iface name.
         * TODO: but it can be used as alternative names?? */
        if (iftype == ARPHRD_INFINIBAND)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                              "Not generating MAC name for infiniband device.");

        /* check for NET_ADDR_PERM, skip random MAC addresses */
        r = device_get_sysattr_unsigned_filtered(dev, "addr_assign_type", &assign_type);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read/parse addr_assign_type: %m");

        if (assign_type != NET_ADDR_PERM)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "addr_assign_type=%u, MAC address is not permanent.", assign_type);

        r = sd_device_get_sysattr_value_filtered(dev, "address", &s);
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
                return log_device_debug_errno(netdevsimdev, r, "Failed to get device sysnum: %m");

        r = safe_atou(sysnum, &addr);
        if (r < 0)
                return log_device_debug_errno(netdevsimdev, r, "Failed to parse device sysnum: %m");

        r = sd_device_get_sysattr_value_filtered(dev, "phys_port_name", &phys_port_name);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get 'phys_port_name' attribute: %m");
        if (isempty(phys_port_name))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                              "The 'phys_port_name' attribute is empty.");

        char str[ALTIFNAMSIZ];
        if (snprintf_ok(str, sizeof str, "%si%un%s", prefix, addr, phys_port_name))
                udev_builtin_add_property(dev, test, "ID_NET_NAME_PATH", str);
        log_device_debug(dev, "Netdevsim identifier: address=%u, port_name=%s %s %s",
                         addr, phys_port_name, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), str + strlen(prefix));
        return 0;
}

static int names_xen(sd_device *dev, const char *prefix, bool test) {
        _cleanup_free_ char *vif = NULL;
        const char *p;
        unsigned id;
        int r;

        assert(dev);
        assert(prefix);

        /* get xen vif "slot" based names. */

        if (!naming_scheme_has(NAMING_XEN_VIF))
                return 0;

        /* check if our direct parent is a Xen VIF device with no other bus in-between */
        if (get_matching_parent(dev, STRV_MAKE("xen"), /* skip_virtio = */ false, NULL) < 0)
                return 0;

        /* Use the vif-n name to extract "n" */
        r = get_first_syspath_component(dev, "/sys/devices/", &vif);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get Xen VIF name: %m");

        p = startswith(vif, "vif-");
        if (!p)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Invalid vif name: %s: %m", vif);

        r = safe_atou_full(p, SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO |
                           SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to parse vif index from '%s': %m", p);

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

        r = device_get_sysattr_unsigned_filtered(dev, "type", &iftype);
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

static int device_is_stacked(sd_device *dev) {
        int ifindex, iflink, r;

        assert(dev);

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r < 0)
                return r;

        r = device_get_sysattr_int_filtered(dev, "iflink", &iflink);
        if (r < 0)
                return r;

        return ifindex != iflink;
}

static int builtin_net_id(UdevEvent *event, int argc, char *argv[], bool test) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        const char *prefix;
        int r;

        /* skip stacked devices, like VLANs, ... */
        r = device_is_stacked(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check if the device is stacked: %m");
        if (r > 0)
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
