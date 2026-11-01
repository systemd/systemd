/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "alloc-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dm-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"

static int dm_ioctl(const char *name, unsigned long request, struct dm_ioctl *dmi) {
        _cleanup_close_ int fd = -EBADF;

        assert(name);
        assert(dmi);

        if (strlen(name) >= sizeof(dmi->name))
                return -ENXIO; /* A device with a name longer than this cannot possibly exist */

        dmi->version[0] = DM_VERSION_MAJOR;
        dmi->version[1] = DM_VERSION_MINOR;
        dmi->version[2] = DM_VERSION_PATCHLEVEL;
        strncpy_exact(dmi->name, name, sizeof(dmi->name));

        /* libdevmapper creates /dev/mapper/control if it doesn't exist, for example if /dev isn't a devtmpfs.
         * Until then, we report that the device doesn't exist. libcryptsetup creates the node when we
         * activate the device. */
        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? -ENXIO : -errno;

        /* The ioctl fails with ENXIO if no device with this name exists. */
        if (ioctl(fd, request, dmi) < 0)
                return -errno;

        return 0;
}

static int dm_get_status(const char *name, struct dm_ioctl *ret) {
        struct dm_ioctl dmi = {
                .data_size = sizeof(dmi),
        };
        int r;

        assert(ret);

        r = dm_ioctl(name, DM_DEV_STATUS, &dmi);
        if (r < 0)
                return r;

        *ret = dmi;
        return 0;
}

int dm_get_devnum(const char *name, dev_t *ret) {
        struct dm_ioctl dmi;
        int r;

        assert(name);

        r = dm_get_status(name, &dmi);
        if (r < 0)
                return r;

        if (ret)
                *ret = (dev_t) dmi.dev;
        return 0;
}

int dm_get_verity_data_devnum(const char *name, dev_t *ret) {
        int r;

        assert(name);
        assert(ret);

        for (size_t size = 4096;; size *= 2) {
                _cleanup_free_ struct dm_ioctl *dmi = NULL;
                _cleanup_free_ char *version = NULL, *data_device = NULL;

                dmi = malloc0(size);
                if (!dmi)
                        return -ENOMEM;

                *dmi = (struct dm_ioctl) {
                        .data_size = size,
                        .data_start = sizeof(*dmi),
                        .flags = DM_STATUS_TABLE_FLAG,
                };

                r = dm_ioctl(name, DM_TABLE_STATUS, dmi);
                if (r < 0)
                        return r;
                if (FLAGS_SET(dmi->flags, DM_BUFFER_FULL_FLAG)) {
                        if (size > UINT32_MAX / 2)
                                return -E2BIG;
                        continue;
                }

                if (dmi->target_count != 1)
                        return -EINVAL;

                const struct dm_target_spec *spec = (const struct dm_target_spec*) ((uint8_t*) dmi + dmi->data_start);
                if (!streq(spec->target_type, "verity"))
                        return -EINVAL;

                const char *params = (const char*) (spec + 1);
                r = extract_many_words(&params, " ", /* flags= */ 0, &version, &data_device);
                if (r < 0)
                        return r;
                if (r != 2)
                        return -EINVAL;

                return parse_devnum(data_device, ret);
        }
}

int dm_open(const char *name, int flags, char **ret_devname) {
        _cleanup_free_ char *devname = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl dmi;
        dev_t devnum;
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
        r = dm_get_status(name, &dmi);
        if (r < 0)
                return r;
        if ((dev_t) dmi.dev != devnum)
                return -ENXIO;

        /* The kernel creates the device node when the first table of the device is loaded, or on kernels
         * older than 5.15 when the device is created. The device only maps anything after its table was
         * activated. Until then, all I/O on the device fails. */
        if (!FLAGS_SET(dmi.flags, DM_ACTIVE_PRESENT_FLAG))
                return -ENXIO;

        if (ret_devname)
                *ret_devname = TAKE_PTR(devname);

        return TAKE_FD(fd);
}
