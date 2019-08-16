/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * compose persistent device path
 *
 * Logic based on Hannes Reinecke's shell script.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "libudev-util.h"
#include "string-util.h"
#include "strv.h"
#include "sysexits.h"
#include "udev-builtin.h"

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

        lun = strtoul(sysnum, NULL, 10);
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

        for (parent = dev; ; ) {
                const char *subsystem;

                if (sd_device_get_subsystem(parent, &subsystem) < 0)
                        break;

                if (!streq(subsystem, subsys))
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

static sd_device *handle_scsi_ata(sd_device *parent, char **path) {
        sd_device *targetdev, *target_parent;
        _cleanup_(sd_device_unrefp) sd_device *atadev = NULL;
        const char *port_no, *sysname;

        assert(parent);
        assert(path);

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

        path_prepend(path, "ata-%s", port_no);
        return parent;
}

static sd_device *handle_scsi_default(sd_device *parent, char **path) {
        sd_device *hostdev;
        int host, bus, target, lun;
        const char *name, *base, *pos;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *dent;
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

        base = strndupa(base, pos - base);
        dir = opendir(base);
        if (!dir)
                return NULL;

        FOREACH_DIRENT_ALL(dent, dir, break) {
                char *rest;
                int i;

                if (dent->d_name[0] == '.')
                        continue;
                if (!IN_SET(dent->d_type, DT_DIR, DT_LNK))
                        continue;
                if (!startswith(dent->d_name, "host"))
                        continue;
                i = strtoul(&dent->d_name[4], &rest, 10);
                if (rest[0] != '\0')
                        continue;
                /*
                 * find the smallest number; the host really needs to export its
                 * own instance number per parent device; relying on the global host
                 * enumeration and plainly rebasing the numbers sounds unreliable
                 */
                if (basenum == -1 || i < basenum)
                        basenum = i;
        }
        if (basenum == -1)
                return hostdev;
        host -= basenum;

        path_prepend(path, "scsi-%u:%u:%u:%u", host, bus, target, lun);
        return hostdev;
}

static sd_device *handle_scsi_hyperv(sd_device *parent, char **path, size_t guid_str_len) {
        sd_device *hostdev;
        sd_device *vmbusdev;
        const char *guid_str;
        _cleanup_free_ char *lun = NULL;
        char guid[39];
        size_t i, k;

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

        for (i = 1, k = 0; i < guid_str_len-1; i++) {
                if (guid_str[i] == '-')
                        continue;
                guid[k++] = guid_str[i];
        }
        guid[k] = '\0';

        format_lun_number(parent, &lun);
        path_prepend(path, "vmbus-%s-%s", guid, lun);
        return parent;
}

static sd_device *handle_scsi(sd_device *parent, char **path, bool *supported_parent) {
        const char *devtype, *id, *name;

        if (sd_device_get_devtype(parent, &devtype) < 0 ||
            !streq(devtype, "scsi_device"))
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
                return handle_scsi_ata(parent, path);

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

static sd_device *handle_usb(sd_device *parent, char **path) {
        const char *devtype, *str, *port;

        if (sd_device_get_devtype(parent, &devtype) < 0)
                return parent;
        if (!STR_IN_SET(devtype, "usb_interface", "usb_device"))
                return parent;

        if (sd_device_get_sysname(parent, &str) < 0)
                return parent;
        port = strchr(str, '-');
        if (!port)
                return parent;
        port++;

        path_prepend(path, "usb-0:%s", port);
        return skip_subsystem(parent, "usb");
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

static int builtin_path_id(sd_device *dev, int argc, char *argv[], bool test) {
        sd_device *parent;
        _cleanup_free_ char *path = NULL;
        bool supported_transport = false;
        bool supported_parent = false;
        const char *subsystem;

        assert(dev);

        /* walk up the chain of devices and compose path */
        parent = dev;
        while (parent) {
                const char *subsys, *sysname;

                if (sd_device_get_subsystem(parent, &subsys) < 0 ||
                    sd_device_get_sysname(parent, &sysname) < 0) {
                        ;
                } else if (streq(subsys, "scsi_tape")) {
                        handle_scsi_tape(parent, &path);
                } else if (streq(subsys, "scsi")) {
                        parent = handle_scsi(parent, &path, &supported_parent);
                        supported_transport = true;
                } else if (streq(subsys, "cciss")) {
                        parent = handle_cciss(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "usb")) {
                        parent = handle_usb(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "bcma")) {
                        parent = handle_bcma(parent, &path);
                        supported_transport = true;
                } else if (streq(subsys, "serio")) {
                        const char *sysnum;

                        if (sd_device_get_sysnum(parent, &sysnum) >= 0 && sysnum) {
                                path_prepend(&path, "serio-%s", sysnum);
                                parent = skip_subsystem(parent, "serio");
                        }
                } else if (streq(subsys, "pci")) {
                        path_prepend(&path, "pci-%s", sysname);
                        parent = skip_subsystem(parent, "pci");
                        supported_parent = true;
                } else if (streq(subsys, "platform")) {
                        path_prepend(&path, "platform-%s", sysname);
                        parent = skip_subsystem(parent, "platform");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "acpi")) {
                        path_prepend(&path, "acpi-%s", sysname);
                        parent = skip_subsystem(parent, "acpi");
                        supported_parent = true;
                } else if (streq(subsys, "xen")) {
                        path_prepend(&path, "xen-%s", sysname);
                        parent = skip_subsystem(parent, "xen");
                        supported_parent = true;
                } else if (streq(subsys, "virtio")) {
                        parent = skip_subsystem(parent, "virtio");
                        supported_transport = true;
                } else if (streq(subsys, "scm")) {
                        path_prepend(&path, "scm-%s", sysname);
                        parent = skip_subsystem(parent, "scm");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ccw")) {
                        path_prepend(&path, "ccw-%s", sysname);
                        parent = skip_subsystem(parent, "ccw");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ccwgroup")) {
                        path_prepend(&path, "ccwgroup-%s", sysname);
                        parent = skip_subsystem(parent, "ccwgroup");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "ap")) {
                        parent = handle_ap(parent, &path);
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "iucv")) {
                        path_prepend(&path, "iucv-%s", sysname);
                        parent = skip_subsystem(parent, "iucv");
                        supported_transport = true;
                        supported_parent = true;
                } else if (streq(subsys, "nvme")) {
                        const char *nsid;

                        if (sd_device_get_sysattr_value(dev, "nsid", &nsid) >= 0) {
                                path_prepend(&path, "nvme-%s", nsid);
                                parent = skip_subsystem(parent, "nvme");
                                supported_parent = true;
                                supported_transport = true;
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
        if (sd_device_get_subsystem(dev, &subsystem) >= 0 &&
            streq(subsystem, "block") &&
            !supported_transport)
                return -ENOENT;

        {
                char tag[UTIL_NAME_SIZE];
                size_t i;
                const char *p;

                /* compose valid udev tag name */
                for (p = path, i = 0; *p; p++) {
                        if ((*p >= '0' && *p <= '9') ||
                            (*p >= 'A' && *p <= 'Z') ||
                            (*p >= 'a' && *p <= 'z') ||
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

                udev_builtin_add_property(dev, test, "ID_PATH", path);
                udev_builtin_add_property(dev, test, "ID_PATH_TAG", tag);
        }

        return 0;
}

const UdevBuiltin udev_builtin_path_id = {
        .name = "path_id",
        .cmd = builtin_path_id,
        .help = "Compose persistent device path",
        .run_once = true,
};
