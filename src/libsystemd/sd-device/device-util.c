/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "strv.h"

int devname_from_devnum(mode_t mode, dev_t devnum, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *devname;
        int r;

        assert(ret);

        if (devnum_is_zero(devnum))
                return device_path_make_inaccessible(mode, ret);

        r = device_new_from_mode_and_devnum(&dev, mode, devnum);
        if (r < 0)
                return r;

        r = sd_device_get_devname(dev, &devname);
        if (r < 0)
                return r;

        return strdup_to(ret, devname);
}

int devname_from_stat_rdev(const struct stat *st, char **ret) {
        assert(st);
        return devname_from_devnum(st->st_mode, st->st_rdev, ret);
}

int device_open_from_devnum(mode_t mode, dev_t devnum, int flags, char **ret_devname) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = device_new_from_mode_and_devnum(&dev, mode, devnum);
        if (r < 0)
                return r;

        fd = sd_device_open(dev, flags);
        if (fd < 0)
                return fd;

        if (ret_devname) {
                const char *devname;

                r = sd_device_get_devname(dev, &devname);
                if (r < 0)
                        return r;

                r = strdup_to(ret_devname, devname);
                if (r < 0)
                        return r;
        }

        return TAKE_FD(fd);
}

static int add_string_field(
                sd_device *device,
                const char *field,
                int (*func)(sd_device *dev, const char **s),
                char ***strv) {

        const char *s;
        int r;

        assert(device);
        assert(field);
        assert(func);
        assert(strv);

        r = func(device, &s);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", field);
        if (r >= 0)
                (void) strv_extend_assignment(strv, field, s);

        return 0;
}

char** device_make_log_fields(sd_device *device) {
        _cleanup_strv_free_ char **strv = NULL;
        dev_t devnum;
        int ifindex;
        sd_device_action_t action;
        uint64_t seqnum, diskseq;
        int r;

        assert(device);

        (void) add_string_field(device, "SYSPATH", sd_device_get_syspath, &strv);
        (void) add_string_field(device, "SUBSYSTEM", sd_device_get_subsystem, &strv);
        (void) add_string_field(device, "DEVTYPE", sd_device_get_devtype, &strv);
        (void) add_string_field(device, "DRIVER", sd_device_get_driver, &strv);
        (void) add_string_field(device, "DEVPATH", sd_device_get_devpath, &strv);
        (void) add_string_field(device, "DEVNAME", sd_device_get_devname, &strv);
        (void) add_string_field(device, "SYSNAME", sd_device_get_sysname, &strv);
        (void) add_string_field(device, "SYSNUM", sd_device_get_sysnum, &strv);

        r = sd_device_get_devnum(device, &devnum);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", "DEVNUM");
        if (r >= 0)
                (void) strv_extendf(&strv, "DEVNUM="DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(devnum));

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", "IFINDEX");
        if (r >= 0)
                (void) strv_extendf(&strv, "IFINDEX=%i", ifindex);

        r = sd_device_get_action(device, &action);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", "ACTION");
        if (r >= 0)
                (void) strv_extendf(&strv, "ACTION=%s", device_action_to_string(action));

        r = sd_device_get_seqnum(device, &seqnum);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", "SEQNUM");
        if (r >= 0)
                (void) strv_extendf(&strv, "SEQNUM=%"PRIu64, seqnum);

        r = sd_device_get_diskseq(device, &diskseq);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"%s\" property, ignoring: %m", "DISKSEQ");
        if (r >= 0)
                (void) strv_extendf(&strv, "DISKSEQ=%"PRIu64, diskseq);

        return TAKE_PTR(strv);
}

int device_in_subsystem_strv(sd_device *device, char * const *subsystems) {
        const char *s;
        int r;

        assert(device);

        r = sd_device_get_subsystem(device, &s);
        if (r == -ENOENT)
                return strv_isempty(subsystems);
        if (r < 0)
                return r;
        return strv_contains(subsystems, s);
}

int device_is_devtype(sd_device *device, const char *devtype) {
        const char *s;
        int r;

        assert(device);

        r = sd_device_get_devtype(device, &s);
        if (r == -ENOENT)
                return !devtype;
        if (r < 0)
                return r;
        return streq_ptr(s, devtype);
}

int device_is_subsystem_devtype(sd_device *device, const char *subsystem, const char *devtype) {
        int r;

        assert(device);

        r = device_in_subsystem(device, subsystem);
        if (r <= 0)
                return r;

        if (!devtype)
                return true;

        return device_is_devtype(device, devtype);
}

int device_sysname_startswith_strv(sd_device *device, char * const *prefixes, const char **ret_suffix) {
        const char *sysname;
        int r;

        assert(device);

        r = sd_device_get_sysname(device, &sysname);
        if (r < 0)
                return r;

        const char *suffix = startswith_strv(sysname, prefixes);
        if (ret_suffix)
                *ret_suffix = suffix;
        return !!suffix;
}

int device_get_seat(sd_device *device, const char **ret) {
        const char *seat = NULL;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_property_value(device, "ID_SEAT", &seat);
        if (r < 0 && r != -ENOENT)
                return r;

        *ret = isempty(seat) ? "seat0" : seat;
        return 0;
}

bool device_property_can_set(const char *property) {
        return property &&
                !STR_IN_SET(property,
                            /* basic properties set by kernel, only in netlink event */
                            "ACTION", "SEQNUM", "SYNTH_UUID",
                            /* basic properties set by kernel, both in netlink event and uevent file */
                            "DEVPATH", "DEVPATH_OLD", "SUBSYSTEM", "DEVTYPE", "DRIVER", "MODALIAS",
                            /* device node */
                            "DEVNAME", "DEVMODE", "DEVUID", "DEVGID", "MAJOR", "MINOR",
                            /* block device */
                            "DISKSEQ", "PARTN",
                            /* network interface (INTERFACE_OLD is set by udevd) */
                            "IFINDEX", "INTERFACE", "INTERFACE_OLD",
                            /* basic properties set by udevd */
                            "DEVLINKS", "TAGS", "CURRENT_TAGS", "USEC_INITIALIZED", "UDEV_DATABASE_VERSION") &&
                /* Similar to SYNTH_UUID, but set based on KEY=VALUE arguments passed by userspace.
                 * See kernel's f36776fafbaa0094390dd4e7e3e29805e0b82730 (v4.13) */
                !startswith(property, "SYNTH_ARG_");
}
