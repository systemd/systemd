/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * compose persistent device path
 *
 * Logic based on Hannes Reinecke's shell script.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/usb/ch11.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "sysexits.h"
#include "udev-builtin.h"
#include "udev-util.h"

_printf_(2,3)
static void path_prepend(char **path, const char *fmt, ...) {
        va_list va;
        _cleanup_free_ char *pre = NULL;
        int r;

        va_start(va, fmt);
        r = vasprintf(&pre, fmt, va);
        va_end(va);
        if (r < 0) {
                log_oom();
                exit(EX_OSERR);
        }

        if (*path) {
                char *new;

                new = strjoin(pre, "-", *path);
                if (!new) {
                        log_oom();
                        exit(EX_OSERR);
                }

                free_and_replace(*path, new);
        } else
                *path = TAKE_PTR(pre);
}

/*
** Linux only supports 32 bit luns.
** See drivers/scsi/scsi_scan.c::scsilun_to_int() for more details.
*/
static int format_lun_number(sd_device *dev, char **path) {
        const char *sysnum;
        unsigned long lun;
        int r;

        r = sd_device_get_sysnum(dev, &sysnum);
        if (r < 0)
                return r;
        if (!sysnum)
                return -ENOENT;

        r = safe_atolu_full(sysnum, 10, &lun);
        if (r < 0)
                return r;
        if (lun < 256)
                /* address method 0, peripheral device addressing with bus id of zero */
                path_prepend(path, "lun-%lu", lun);
        else
                /* handle all other lun addressing methods by using a variant of the original lun format */
                path_prepend(path, "lun-0x%04lx%04lx00000000", lun & 0xffff, (lun >> 16) & 0xffff);

        return 0;
}

static sd_device *skip_subsystem(sd_device *dev, const char *subsys) {
        sd_device *parent;

        assert(dev);
        assert(subsys);

        /* Unlike the function name, this drops multiple parent devices EXCEPT FOR THE LAST ONE.
         * The last one will be dropped at the end of the loop in builtin_path_id().
         * E.g.
         * Input:  /sys/devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0
         * Output: /sys/devices/pci0000:00/0000:00:14.0/usb1
         */

        for (parent = dev; ; ) {
                if (!device_in_subsystem(parent, subsys))
                        break;

                dev = parent;
                if (sd_device_get_parent(dev, &parent) < 0)
                        break;
        }

        return dev;
}

static sd_device *handle_scsi_fibre_channel(sd_device *parent, char **path) {
        sd_device *targetdev;
        _cleanup_(sd_device_unrefp) sd_device *fcdev = NULL;
        const char *port, *sysname;
        _cleanup_free_ char *lun = NULL;

        assert(parent);
        assert(path);

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target", &targetdev) < 0)
                return NULL;
        if (sd_device_get_sysname(targetdev, &sysname) < 0)
                return NULL;
        if (sd_device_new_from_subsystem_sysname(&fcdev, "fc_transport", sysname) < 0)
                return NULL;
        if (sd_device_get_sysattr_value(fcdev, "port_name", &port) < 0)
                return NULL;

        format_lun_number(parent, &lun);
        path_prepend(path, "fc-%s-%s", port, lun);
        return parent;
}

static sd_device *handle_scsi_sas_wide_port(sd_device *parent, char **path) {
        sd_device *targetdev, *target_parent;
        _cleanup_(sd_device_unrefp) sd_device *sasdev = NULL;
        const char *sas_address, *sysname;
        _cleanup_free_ char *lun = NULL;

        assert(parent);
        assert(path);

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target", &targetdev) < 0)
                return NULL;
        if (sd_device_get_parent(targetdev, &target_parent) < 0)
                return NULL;
        if (sd_device_get_sysname(target_parent, &sysname) < 0)
                return NULL;
        if (sd_device_new_from_subsystem_sysname(&sasdev, "sas_device", sysname) < 0)
                return NULL;
        if (sd_device_get_sysattr_value(sasdev, "sas_address", &sas_address) < 0)
                return NULL;

        format_lun_number(parent, &lun);
        path_prepend(path, "sas-%s-%s", sas_address, lun);
        return parent;
}

static sd_device *handle_scsi_sas(sd_device *parent, char **path) {
        sd_device *targetdev, *target_parent, *port, *expander;
        _cleanup_(sd_device_unrefp) sd_device *target_sasdev = NULL, *expander_sasdev = NULL, *port_sasdev = NULL;
        const char *sas_address = NULL;
        const char *phy_id;
        const char *phy_count, *sysname;
        _cleanup_free_ char *lun = NULL;

        assert(parent);
        assert(path);

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target", &targetdev) < 0)
                return NULL;
        if (sd_device_get_parent(targetdev, &target_parent) < 0)
                return NULL;
        if (sd_device_get_sysname(target_parent, &sysname) < 0)
                return NULL;
        /* Get sas device */
        if (sd_device_new_from_subsystem_sysname(&target_sasdev, "sas_device", sysname) < 0)
                return NULL;
        /* The next parent is sas port */
        if (sd_device_get_parent(target_parent, &port) < 0)
                return NULL;
        if (sd_device_get_sysname(port, &sysname) < 0)
                return NULL;
        /* Get port device */
        if (sd_device_new_from_subsystem_sysname(&port_sasdev, "sas_port", sysname) < 0)
                return NULL;
        if (sd_device_get_sysattr_value(port_sasdev, "num_phys", &phy_count) < 0)
                return NULL;

        /* Check if we are simple disk */
        if (strncmp(phy_count, "1", 2) != 0)
                return handle_scsi_sas_wide_port(parent, path);

        /* Get connected phy */
        if (sd_device_get_sysattr_value(target_sasdev, "phy_identifier", &phy_id) < 0)
                return NULL;

        /* The port's parent is either hba or expander */
        if (sd_device_get_parent(port, &expander) < 0)
                return NULL;

        if (sd_device_get_sysname(expander, &sysname) < 0)
                return NULL;
        /* Get expander device */
        if (sd_device_new_from_subsystem_sysname(&expander_sasdev, "sas_device", sysname) >= 0) {
                /* Get expander's address */
                if (sd_device_get_sysattr_value(expander_sasdev, "sas_address", &sas_address) < 0)
                        return NULL;
        }

        format_lun_number(parent, &lun);
        if (sas_address)
                 path_prepend(path, "sas-exp%s-phy%s-%s", sas_address, phy_id, lun);
        else
                 path_prepend(path, "sas-phy%s-%s", phy_id, lun);

        return parent;
}

static sd_device *handle_scsi_iscsi(sd_device *parent, char **path) {
        sd_device *transportdev;
        _cleanup_(sd_device_unrefp) sd_device *sessiondev = NULL, *conndev = NULL;
        const char *target, *connname, *addr, *port;
        _cleanup_free_ char *lun = NULL;
        const char *sysname, *sysnum;

        assert(parent);
        assert(path);

        /* find iscsi session */
        for (transportdev = parent; ; ) {

                if (sd_device_get_parent(transportdev, &transportdev) < 0)
                        return NULL;
                if (sd_device_get_sysname(transportdev, &sysname) < 0)
                        return NULL;
                if (startswith(sysname, "session"))
                        break;
        }

        /* find iscsi session device */
        if (sd_device_new_from_subsystem_sysname(&sessiondev, "iscsi_session", sysname) < 0)
                return NULL;

        if (sd_device_get_sysattr_value(sessiondev, "targetname", &target) < 0)
                return NULL;

        if (sd_device_get_sysnum(transportdev, &sysnum) < 0 || !sysnum)
                return NULL;
        connname = strjoina("connection", sysnum, ":0");
        if (sd_device_new_from_subsystem_sysname(&conndev, "iscsi_connection", connname) < 0)
                return NULL;

        if (sd_device_get_sysattr_value(conndev, "persistent_address", &addr) < 0)
                return NULL;
        if (sd_device_get_sysattr_value(conndev, "persistent_port", &port) < 0)
                return NULL;

        format_lun_number(parent, &lun);
        path_prepend(path, "ip-%s:%s-iscsi-%s-%s", addr, port, target, lun);
        return parent;
}

static sd_device *handle_scsi_ata(sd_device *parent, char **path, char **compat_path) {
        sd_device *targetdev, *target_parent;
        _cleanup_(sd_device_unrefp) sd_device *atadev = NULL;
        const char *port_no, *sysname, *name;
        unsigned host, bus, target, lun;

        assert(parent);
        assert(path);

        if (sd_device_get_sysname(parent, &name) < 0)
                return NULL;
        if (sscanf(name, "%u:%u:%u:%u", &host, &bus, &target, &lun) != 4)
                return NULL;

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host", &targetdev) < 0)
                return NULL;

        if (sd_device_get_parent(targetdev, &target_parent) < 0)
                return NULL;

        if (sd_device_get_sysname(target_parent, &sysname) < 0)
                return NULL;
        if (sd_device_new_from_subsystem_sysname(&atadev, "ata_port", sysname) < 0)
                return NULL;

        if (sd_device_get_sysattr_value(atadev, "port_no", &port_no) < 0)
                return NULL;

        if (bus != 0)
                /* Devices behind port multiplier have a bus != 0 */
                path_prepend(path, "ata-%s.%u.0", port_no, bus);
        else
                /* Master/slave are distinguished by target id */
                path_prepend(path, "ata-%s.%u", port_no, target);

        /* old compatible persistent link for ATA devices */
        if (compat_path)
                path_prepend(compat_path, "ata-%s", port_no);

        return parent;
}

static sd_device *handle_scsi_default(sd_device *parent, char **path) {
        sd_device *hostdev;
        int host, bus, target, lun;
        const char *name, *base, *pos;
        _cleanup_closedir_ DIR *dir = NULL;
        int basenum = -1;

        assert(parent);
        assert(path);

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host", &hostdev) < 0)
                return NULL;

        if (sd_device_get_sysname(parent, &name) < 0)
                return NULL;
        if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
                return NULL;

        /*
         * Rebase host offset to get the local relative number
         *
         * Note: This is by definition racy, unreliable and too simple.
         * Please do not copy this model anywhere. It's just a left-over
         * from the time we had no idea how things should look like in
         * the end.
         *
         * Making assumptions about a global in-kernel counter and use
         * that to calculate a local offset is a very broken concept. It
         * can only work as long as things are in strict order.
         *
         * The kernel needs to export the instance/port number of a
         * controller directly, without the need for rebase magic like
         * this. Manual driver unbind/bind, parallel hotplug/unplug will
         * get into the way of this "I hope it works" logic.
         */

        if (sd_device_get_syspath(hostdev, &base) < 0)
                return NULL;
        pos = strrchr(base, '/');
        if (!pos)
                return NULL;

        base = strndupa_safe(base, pos - base);
        dir = opendir(base);
        if (!dir)
                return NULL;

        FOREACH_DIRENT_ALL(de, dir, break) {
                unsigned i;

                if (de->d_name[0] == '.')
                        continue;
                if (!IN_SET(de->d_type, DT_DIR, DT_LNK))
                        continue;
                if (!startswith(de->d_name, "host"))
                        continue;
                if (safe_atou_full(&de->d_name[4], 10, &i) < 0)
                        continue;
                /*
                 * find the smallest number; the host really needs to export its
                 * own instance number per parent device; relying on the global host
                 * enumeration and plainly rebasing the numbers sounds unreliable
                 */
                if (basenum == -1 || (int) i < basenum)
                        basenum = i;
        }
        if (basenum == -1)
                return hostdev;
        host -= basenum;

        path_prepend(path, "scsi-%i:%i:%i:%i", host, bus, target, lun);
        return hostdev;
}

static sd_device *handle_scsi_hyperv(sd_device *parent, char **path, size_t guid_str_len) {
        sd_device *hostdev;
        sd_device *vmbusdev;
        const char *guid_str;
        _cleanup_free_ char *lun = NULL;
        char guid[39];

        assert(parent);
        assert(path);
        assert(guid_str_len < sizeof(guid));

        if (sd_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host", &hostdev) < 0)
                return NULL;

        if (sd_device_get_parent(hostdev, &vmbusdev) < 0)
                return NULL;

        if (sd_device_get_sysattr_value(vmbusdev, "device_id", &guid_str) < 0)
                return NULL;

        if (strlen(guid_str) < guid_str_len || guid_str[0] != '{' || guid_str[guid_str_len-1] != '}')
                return NULL;

        size_t k = 0;
        for (size_t i = 1; i < guid_str_len-1; i++) {
                if (guid_str[i] == '-')
                        continue;
                guid[k++] = guid_str[i];
        }
        guid[k] = '\0';

        format_lun_number(parent, &lun);
        path_prepend(path, "vmbus-%s-%s", guid, lun);
        return parent;
}

static sd_device *handle_scsi(sd_device *parent, char **path, char **compat_path, bool *supported_parent) {
        const char *id, *name;

        if (!device_is_devtype(parent, "scsi_device"))
                return parent;

        /* firewire */
        if (sd_device_get_sysattr_value(parent, "ieee1394_id", &id) >= 0) {
                path_prepend(path, "ieee1394-0x%s", id);
                *supported_parent = true;
                return skip_subsystem(parent, "scsi");
        }

        /* scsi sysfs does not have a "subsystem" for the transport */
        if (sd_device_get_syspath(parent, &name) < 0)
                return NULL;

        if (strstr(name, "/rport-")) {
                *supported_parent = true;
                return handle_scsi_fibre_channel(parent, path);
        }

        if (strstr(name, "/end_device-")) {
                *supported_parent = true;
                return handle_scsi_sas(parent, path);
        }

        if (strstr(name, "/session")) {
                *supported_parent = true;
                return handle_scsi_iscsi(parent, path);
        }

        if (strstr(name, "/ata"))
                return handle_scsi_ata(parent, path, compat_path);

        if (strstr(name, "/vmbus_"))
                return handle_scsi_hyperv(parent, path, 37);
        else if (strstr(name, "/VMBUS"))
                return handle_scsi_hyperv(parent, path, 38);

        return handle_scsi_default(parent, path);
}

static sd_device *handle_cciss(sd_device *parent, char **path) {
        const char *str;
        unsigned controller, disk;

        if (sd_device_get_sysname(parent, &str) < 0)
                return NULL;
        if (sscanf(str, "c%ud%u%*s", &controller, &disk) != 2)
                return NULL;

        path_prepend(path, "cciss-disk%u", disk);
        return skip_subsystem(parent, "cciss");
}

static void handle_scsi_tape(sd_device *dev, char **path) {
        const char *name;

        /* must be the last device in the syspath */
        if (*path)
                return;

        if (sd_device_get_sysname(dev, &name) < 0)
                return;

        if (startswith(name, "nst") && strchr("lma", name[3]))
                path_prepend(path, "nst%c", name[3]);
        else if (startswith(name, "st") && strchr("lma", name[2]))
                path_prepend(path, "st%c", name[2]);
}

static int get_usb_revision(sd_device *dev) {
        uint8_t protocol;
        const char *s;
        int r;

        assert(dev);

        /* Returns usb revision 1, 2, or 3. */

        r = sd_device_get_sysattr_value(dev, "bDeviceProtocol", &s);
        if (r < 0)
                return r;

        r = safe_atou8_full(s, 16, &protocol);
        if (r < 0)
                return r;

        switch (protocol) {
        case USB_HUB_PR_HS_NO_TT: /* Full speed hub (USB1) or Hi-speed hub without TT (USB2) */

                /* See speed_show() in drivers/usb/core/sysfs.c of the kernel. */
                r = sd_device_get_sysattr_value(dev, "speed", &s);
                if (r < 0)
                        return r;

                if (streq(s, "480"))
                        return 2;

                return 1;

        case USB_HUB_PR_HS_SINGLE_TT: /* Hi-speed hub with single TT */
        case USB_HUB_PR_HS_MULTI_TT: /* Hi-speed hub with multiple TT */
                return 2;

        case USB_HUB_PR_SS: /* Super speed hub */
                return 3;

        default:
                return -EPROTONOSUPPORT;
        }
}

static sd_device *handle_usb(sd_device *parent, char **path) {
        const char *str, *port;
        int r;

        if (!device_is_devtype(parent, "usb_interface") && !device_is_devtype(parent, "usb_device"))
                return parent;

        if (sd_device_get_sysname(parent, &str) < 0)
                return parent;
        port = strchr(str, '-');
        if (!port)
                return parent;
        port++;

        parent = skip_subsystem(parent, "usb");
        if (!parent)
                return NULL;

        /* USB host number may change across reboots (and probably even without reboot). The part after USB
         * host number is determined by device topology and so does not change. Hence, drop the host number
         * and always use '0' instead.
         *
         * xHCI host controllers may register two (or more?) USB root hubs for USB 2.0 and USB 3.0, and the
         * sysname, whose host number replaced with 0, of a device under the hubs may conflict with others.
         * To avoid the conflict, let's include the USB revision of the root hub to the PATH_ID.
         * See issue https://github.com/systemd/systemd/issues/19406 for more details. */
        r = get_usb_revision(parent);
        if (r < 0) {
                log_device_debug_errno(parent, r, "Failed to get the USB revision number, ignoring: %m");
                path_prepend(path, "usb-0:%s", port);
        } else {
                assert(r > 0);
                path_prepend(path, "usbv%i-0:%s", r, port);
        }

        return parent;
}

static sd_device *handle_bcma(sd_device *parent, char **path) {
        const char *sysname;
        unsigned core;

        if (sd_device_get_sysname(parent, &sysname) < 0)
                return NULL;
        if (sscanf(sysname, "bcma%*u:%u", &core) != 1)
                return NULL;

        path_prepend(path, "bcma-%u", core);
        return parent;
}

/* Handle devices of AP bus in System z platform. */
static sd_device *handle_ap(sd_device *parent, char **path) {
        const char *type, *func;

        assert(parent);
        assert(path);

        if (sd_device_get_sysattr_value(parent, "type", &type) >= 0 &&
            sd_device_get_sysattr_value(parent, "ap_functions", &func) >= 0)
                path_prepend(path, "ap-%s-%s", type, func);
        else {
                const char *sysname;

                if (sd_device_get_sysname(parent, &sysname) >= 0)
                        path_prepend(path, "ap-%s", sysname);
        }

        return skip_subsystem(parent, "ap");
}

static int find_real_nvme_parent(sd_device *dev, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *nvme = NULL;
        const char *sysname, *end, *devpath;
        int r;

        /* If the device belongs to "nvme-subsystem" (not to be confused with "nvme"), which happens when
         * NVMe multipathing is enabled in the kernel (/sys/module/nvme_core/parameters/multipath is Y),
         * then the syspath is something like the following:
         *   /sys/devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1
         * Hence, we need to find the 'real parent' in "nvme" subsystem, e.g,
         *   /sys/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0 */

        assert(dev);
        assert(ret);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return r;

        /* The sysname format of nvme block device is nvme%d[c%d]n%d[p%d], e.g. nvme0n1p2 or nvme0c1n2.
         * (Note, nvme device with 'c' can be ignored, as they are hidden. )
         * The sysname format of nvme subsystem device is nvme%d.
         * See nvme_alloc_ns() and nvme_init_ctrl() in drivers/nvme/host/core.c for more details. */
        end = startswith(sysname, "nvme");
        if (!end)
                return -ENXIO;

        end += strspn(end, DIGITS);
        sysname = strndupa_safe(sysname, end - sysname);

        r = sd_device_new_from_subsystem_sysname(&nvme, "nvme", sysname);
        if (r < 0)
                return r;

        r = sd_device_get_devpath(nvme, &devpath);
        if (r < 0)
                return r;

        /* If the 'real parent' is (still) virtual, e.g. for nvmf disks, refuse to set ID_PATH. */
        if (path_startswith(devpath, "/devices/virtual/"))
                return -ENXIO;

        *ret = TAKE_PTR(nvme);
        return 0;
}

static void add_id_with_usb_revision(sd_device *dev, bool test, char *path) {
        char *p;
        int r;

        assert(dev);
        assert(path);

        /* When the path contains the USB revision, let's adds ID_PATH_WITH_USB_REVISION property and
         * drop the version specifier for later use. */

        p = strstrafter(path, "-usbv");
        if (!p)
                return;
        if (!ascii_isdigit(p[0]))
                return;
        if (p[1] != '-')
                return;

        r = udev_builtin_add_property(dev, test, "ID_PATH_WITH_USB_REVISION", path);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to add ID_PATH_WITH_USB_REVISION property, ignoring: %m");

        /* Drop the USB revision specifier for backward compatibility. */
        memmove(p - 1, p + 1, strlen(p + 1) + 1);
}

static void add_id_tag(sd_device *dev, bool test, const char *path) {
        char tag[UDEV_NAME_SIZE];
        size_t i = 0;
        int r;

        /* compose valid udev tag name */
        for (const char *p = path; *p; p++) {
                if (ascii_isdigit(*p) ||
                    ascii_isalpha(*p) ||
                    *p == '-') {
                        tag[i++] = *p;
                        continue;
                }

                /* skip all leading '_' */
                if (i == 0)
                        continue;

                /* avoid second '_' */
                if (tag[i-1] == '_')
                        continue;

                tag[i++] = '_';
        }
        /* strip trailing '_' */
        while (i > 0 && tag[i-1] == '_')
                i--;
        tag[i] = '\0';

        r = udev_builtin_add_property(dev, test, "ID_PATH_TAG", tag);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to add ID_PATH_TAG property, ignoring: %m");
}

static int builtin_path_id(UdevEvent *event, int argc, char *argv[], bool test) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_(sd_device_unrefp) sd_device *dev_other_branch = NULL;
        _cleanup_free_ char *path = NULL, *compat_path = NULL;
        bool supported_transport = false, supported_parent = false;
        int r;

        /* walk up the chain of devices and compose path */
        for (sd_device *parent = dev; parent; ) {
                const char *sysname;

                if (sd_device_get_sysname(parent, &sysname) < 0) {
                        ;
                } else if (device_in_subsystem(parent, "scsi_tape")) {
                        handle_scsi_tape(parent, &path);
                } else if (device_in_subsystem(parent, "scsi")) {
                        parent = handle_scsi(parent, &path, &compat_path, &supported_parent);
                        supported_transport = true;
                } else if (device_in_subsystem(parent, "cciss")) {
                        parent = handle_cciss(parent, &path);
                        supported_transport = true;
                } else if (device_in_subsystem(parent, "usb")) {
                        parent = handle_usb(parent, &path);
                        supported_transport = true;
                } else if (device_in_subsystem(parent, "bcma")) {
                        parent = handle_bcma(parent, &path);
                        supported_transport = true;
                } else if (device_in_subsystem(parent, "serio")) {
                        const char *sysnum;

                        if (sd_device_get_sysnum(parent, &sysnum) >= 0 && sysnum) {
                                path_prepend(&path, "serio-%s", sysnum);
                                parent = skip_subsystem(parent, "serio");
                        }
                } else if (device_in_subsystem(parent, "pci")) {
                        path_prepend(&path, "pci-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "pci-%s", sysname);
                        parent = skip_subsystem(parent, "pci");
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "platform")) {
                        path_prepend(&path, "platform-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "platform-%s", sysname);
                        parent = skip_subsystem(parent, "platform");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "amba")) {
                        path_prepend(&path, "amba-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "amba-%s", sysname);
                        parent = skip_subsystem(parent, "amba");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "acpi")) {
                        path_prepend(&path, "acpi-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "acpi-%s", sysname);
                        parent = skip_subsystem(parent, "acpi");
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "xen")) {
                        path_prepend(&path, "xen-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "xen-%s", sysname);
                        parent = skip_subsystem(parent, "xen");
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "virtio")) {
                        parent = skip_subsystem(parent, "virtio");
                        supported_transport = true;
                } else if (device_in_subsystem(parent, "scm")) {
                        path_prepend(&path, "scm-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "scm-%s", sysname);
                        parent = skip_subsystem(parent, "scm");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "ccw")) {
                        path_prepend(&path, "ccw-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "ccw-%s", sysname);
                        parent = skip_subsystem(parent, "ccw");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "ccwgroup")) {
                        path_prepend(&path, "ccwgroup-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "ccwgroup-%s", sysname);
                        parent = skip_subsystem(parent, "ccwgroup");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "ap")) {
                        parent = handle_ap(parent, &path);
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "iucv")) {
                        path_prepend(&path, "iucv-%s", sysname);
                        if (compat_path)
                                path_prepend(&compat_path, "iucv-%s", sysname);
                        parent = skip_subsystem(parent, "iucv");
                        supported_transport = true;
                        supported_parent = true;
                } else if (device_in_subsystem(parent, "nvme") || device_in_subsystem(parent, "nvme-subsystem")) {
                        const char *nsid;

                        if (sd_device_get_sysattr_value(dev, "nsid", &nsid) >= 0) {
                                path_prepend(&path, "nvme-%s", nsid);
                                if (compat_path)
                                        path_prepend(&compat_path, "nvme-%s", nsid);

                                if (device_in_subsystem(parent, "nvme-subsystem")) {
                                        r = find_real_nvme_parent(dev, &dev_other_branch);
                                        if (r < 0)
                                                return r;

                                        parent = dev_other_branch;
                                }

                                parent = skip_subsystem(parent, "nvme");
                                supported_parent = true;
                                supported_transport = true;
                        }
                } else if (device_in_subsystem(parent, "spi")) {
                        const char *sysnum;

                        if (sd_device_get_sysnum(parent, &sysnum) >= 0 && sysnum) {
                                path_prepend(&path, "cs-%s", sysnum);
                                parent = skip_subsystem(parent, "spi");
                        }
                }

                if (!parent)
                        break;
                if (sd_device_get_parent(parent, &parent) < 0)
                        break;
        }

        if (!path)
                return -ENOENT;

        /*
         * Do not return devices with an unknown parent device type. They
         * might produce conflicting IDs if the parent does not provide a
         * unique and predictable name.
         */
        if (!supported_parent)
                return -ENOENT;

        /*
         * Do not return block devices without a well-known transport. Some
         * devices do not expose their buses and do not provide a unique
         * and predictable name that way.
         */
        if (device_in_subsystem(dev, "block") && !supported_transport)
                return -ENOENT;

        add_id_with_usb_revision(dev, test, path);

        r = udev_builtin_add_property(dev, test, "ID_PATH", path);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to add ID_PATH property, ignoring: %m");

        add_id_tag(dev, test, path);

        /*
         * Compatible link generation for ATA devices
         * we assign compat_link to the env variable
         * ID_PATH_ATA_COMPAT
         */
        if (compat_path)
                udev_builtin_add_property(dev, test, "ID_PATH_ATA_COMPAT", compat_path);

        return 0;
}

const UdevBuiltin udev_builtin_path_id = {
        .name = "path_id",
        .cmd = builtin_path_id,
        .help = "Compose persistent device path",
        .run_once = true,
};
