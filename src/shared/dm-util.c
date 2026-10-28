/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "alloc-util.h"
#include "device-util.h"
#include "dm-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "parse-util.h"
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

        fd = xopenat(AT_FDCWD, "/dev/mapper/control", O_RDWR);
        if (fd < 0)
                return fd;

        if (ioctl(fd, DM_TARGET_MSG, &message))
                return -errno;

        return 0;
}

int dm_table_status(dev_t devnum, char **ret_target_type, char **ret_params) {
        /* The status line of a single verity target, with a root hash and a salt of at most 640 hex
         * characters, is much shorter than this. */
        const size_t size = 16U * 1024U;
        _cleanup_free_ struct dm_ioctl *dmi = NULL;
        _cleanup_close_ int fd = -EBADF;

        assert(ret_target_type);
        assert(ret_params);

        fd = xopenat(AT_FDCWD, "/dev/mapper/control", O_RDWR);
        if (fd < 0)
                return fd;

        dmi = malloc0(size);
        if (!dmi)
                return -ENOMEM;

        /* The kernel decodes .dev with huge_decode_dev(). We encode the device number the same way,
         * instead of relying on how the C library encodes dev_t. */
        *dmi = (struct dm_ioctl) {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = size,
                .data_start = sizeof(struct dm_ioctl),
                .flags = DM_STATUS_TABLE_FLAG,
                .dev = (minor(devnum) & 0xffU) | (major(devnum) << 8) | ((uint64_t) (minor(devnum) & ~0xffU) << 12),
        };

        if (ioctl(fd, DM_TABLE_STATUS, dmi) < 0)
                return -errno;

        if (FLAGS_SET(dmi->flags, DM_BUFFER_FULL_FLAG))
                return -ENOBUFS;
        if (dmi->target_count == 0)
                return -ENXIO;
        if (dmi->target_count > 1)
                return -ENOTUNIQ;

        const struct dm_target_spec *spec = (const struct dm_target_spec*) ((const uint8_t*) dmi + dmi->data_start);

        _cleanup_free_ char *target_type = strdup(spec->target_type);
        if (!target_type)
                return -ENOMEM;

        char *params = strdup((const char*) (spec + 1));
        if (!params)
                return -ENOMEM;

        *ret_target_type = TAKE_PTR(target_type);
        *ret_params = params;
        return 0;
}

int dm_verity_table_signed(const char *params, const char *root_hash) {
        unsigned n_opts;
        int r;

        assert(params);
        assert(root_hash);

        /* The table of a verity target has the following fields, followed by the optional arguments:
         * <version> <data device> <hash device> <data block size> <hash block size> <number of data blocks>
         * <hash start block> <algorithm> <root hash> <salt> */
        for (unsigned i = 0; i < 10; i++) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&params, &word, /* separators= */ NULL, /* flags= */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                if (i == 8 && !strcaseeq(word, root_hash))
                        return -ESTALE;
        }

        _cleanup_free_ char *word = NULL;
        r = extract_first_word(&params, &word, /* separators= */ NULL, /* flags= */ 0);
        if (r < 0)
                return r;
        if (r == 0)
                return false;

        r = safe_atou(word, &n_opts);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < n_opts; i++) {
                word = mfree(word);

                r = extract_first_word(&params, &word, /* separators= */ NULL, /* flags= */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                /* The kernel only loads a table with this argument if it validated the signature. */
                if (streq(word, "root_hash_sig_key_desc"))
                        return true;
        }

        return false;
}

static int dm_get_status(const char *name, struct dm_ioctl *ret) {
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
        assert(ret);

        if (strlen(name) >= sizeof(dmi.name))
                return -ENXIO; /* A device with a name longer than this cannot possibly exist */

        strncpy_exact(dmi.name, name, sizeof(dmi.name));

        /* libdevmapper creates /dev/mapper/control if it doesn't exist, for example if /dev isn't a devtmpfs.
         * Until then, we report that the device doesn't exist. libcryptsetup creates the node when we
         * activate the device. */
        fd = xopenat(AT_FDCWD, "/dev/mapper/control", O_RDWR);
        if (fd == -ENOENT)
                return -ENXIO;
        if (fd < 0)
                return fd;

        /* The ioctl fails with ENXIO if no device with this name exists. */
        if (ioctl(fd, DM_DEV_STATUS, &dmi) < 0)
                return -errno;

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

                fd = xopenat(AT_FDCWD, devname, flags);
                if (fd < 0)
                        return fd;

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
