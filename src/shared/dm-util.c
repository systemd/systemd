/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "device-util.h"
#include "dm-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"

int dm_deferred_remove_cancel(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        struct combined {
                struct dm_ioctl dm_ioctl;
                struct dm_target_msg dm_target_msg;
        } _packed_;

        union message {
                struct combined combined;
                struct {
                        uint8_t space[offsetof(struct combined, dm_target_msg.message)];
                        char text[STRLEN("@cancel_deferred_remove") + 1];
                } _packed_;
        } message = {
                .combined.dm_ioctl = {
                        .version = {
                                DM_VERSION_MAJOR,
                                DM_VERSION_MINOR,
                                DM_VERSION_PATCHLEVEL
                        },
                        .data_size = sizeof(union message),
                        .data_start = offsetof(union message, combined.dm_target_msg),
                },
        };

        assert(name);

        if (strlen(name) >= sizeof(message.combined.dm_ioctl.name))
                return -ENODEV; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(message.combined.dm_ioctl.name, name, sizeof(message.combined.dm_ioctl.name));
        strncpy_exact(message.text, "@cancel_deferred_remove", sizeof(message.text));

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, DM_TARGET_MSG, &message))
                return -errno;

        return 0;
}

int dm_get_devnum(const char *name, dev_t *ret) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl dmi = {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = sizeof(dmi),
        };

        assert(name);

        if (strlen(name) >= sizeof(dmi.name))
                return -ENXIO; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(dmi.name, name, sizeof(dmi.name));

        /* libdevmapper creates /dev/mapper/control if it doesn't exist, for example if /dev isn't a devtmpfs.
         * Until then, we report that the device doesn't exist. libcryptsetup creates the node when we
         * activate the device. */
        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? -ENXIO : -errno;

        /* The ioctl fails with ENXIO if no device with this name exists. */
        if (ioctl(fd, DM_DEV_STATUS, &dmi) < 0)
                return -errno;

        if (ret)
                *ret = (dev_t) dmi.dev;
        return 0;
}

int dm_open(const char *name, int flags, char **ret_devname) {
        _cleanup_free_ char *devname = NULL;
        _cleanup_close_ int fd = -EBADF;
        dev_t devnum, devnum_after;
        int r;

        assert(name);

        r = dm_get_devnum(name, &devnum);
        if (r < 0)
                return r;

        fd = device_open_from_devnum(S_IFBLK, devnum, flags, ret_devname ? &devname : NULL);
        if (fd == -ENOENT) {
                /* /dev/dm-N doesn't exist if /dev isn't a devtmpfs. If udev doesn't run either, libdevmapper
                 * creates /dev/mapper/<name> itself. */
                devname = path_join("/dev/mapper", name);
                if (!devname)
                        return -ENOMEM;

                fd = open(devname, flags);
                if (fd < 0)
                        return -errno;

                struct stat st;
                if (fstat(fd, &st) < 0)
                        return -errno;
                if (stat_verify_block(&st) < 0 || st.st_rdev != devnum)
                        return -ENXIO;
        }
        if (fd < 0)
                return fd;

        /* Another process can remove the device after we look up its number. The kernel can then give the
         * number to a new device. A device that we keep open can't be removed, so if the name still refers
         * to the same number now, we opened the device with this name. */
        r = dm_get_devnum(name, &devnum_after);
        if (r < 0)
                return r;
        if (devnum_after != devnum)
                return -ENXIO;

        if (ret_devname)
                *ret_devname = TAKE_PTR(devname);

        return TAKE_FD(fd);
}
