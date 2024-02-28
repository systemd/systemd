/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "strv.h"

int devname_from_devnum(mode_t mode, dev_t devnum, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *s = NULL;
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

        s = strdup(devname);
        if (!s)
                return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

int device_open_from_devnum(mode_t mode, dev_t devnum, int flags, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = device_new_from_mode_and_devnum(&dev, mode, devnum);
        if (r < 0)
                return r;

        fd = sd_device_open(dev, flags);
        if (fd < 0)
                return fd;

        if (ret) {
                const char *devname;
                char *s;

                r = sd_device_get_devname(dev, &devname);
                if (r < 0)
                        return r;

                s = strdup(devname);
                if (!s)
                        return -ENOMEM;

                *ret = s;
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
                log_device_debug_errno(device, r, "Failed to get device \"DEVNUM\" property, ignoring: %m");
        if (r >= 0)
                (void) strv_extendf(&strv, "DEVNUM="DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(devnum));

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"IFINDEX\" property, ignoring: %m");
        if (r >= 0)
                (void) strv_extendf(&strv, "IFINDEX=%i", ifindex);

        r = sd_device_get_action(device, &action);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"ACTION\" property, ignoring: %m");
        if (r >= 0)
                (void) strv_extendf(&strv, "ACTION=%s", device_action_to_string(action));

        r = sd_device_get_seqnum(device, &seqnum);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"SEQNUM\" property, ignoring: %m");
        if (r >= 0)
                (void) strv_extendf(&strv, "SEQNUM=%"PRIu64, seqnum);

        r = sd_device_get_diskseq(device, &diskseq);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get device \"DISKSEQ\" property, ignoring: %m");
        if (r >= 0)
                (void) strv_extendf(&strv, "DISKSEQ=%"PRIu64, diskseq);

        return TAKE_PTR(strv);
}

bool device_in_subsystem(sd_device *device, const char *subsystem) {
        const char *s = NULL;

        assert(device);

        (void) sd_device_get_subsystem(device, &s);
        return streq_ptr(s, subsystem);
}

bool device_is_devtype(sd_device *device, const char *devtype) {
        const char *s = NULL;

        assert(device);

        (void) sd_device_get_devtype(device, &s);
        return streq_ptr(s, devtype);
}
