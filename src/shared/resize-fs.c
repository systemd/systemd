/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/btrfs.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

#include "blockdev-util.h"
#include "fs-util.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "missing_xfs.h"
#include "resize-fs.h"
#include "stat-util.h"

int resize_fs(int fd, uint64_t sz, uint64_t *ret_size) {
        struct statfs sfs;

        assert(fd >= 0);

        /* Rounds down to next block size */

        if (sz <= 0 || sz == UINT64_MAX)
                return -ERANGE;

        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        if (is_fs_type(&sfs, EXT4_SUPER_MAGIC)) {
                uint64_t u;

                if (sz < EXT4_MINIMAL_SIZE)
                        return -ERANGE;

                u = sz / sfs.f_bsize;

                if (ioctl(fd, EXT4_IOC_RESIZE_FS, &u) < 0)
                        return -errno;

                if (ret_size)
                        *ret_size = u * sfs.f_bsize;

        } else if (is_fs_type(&sfs, BTRFS_SUPER_MAGIC)) {
                struct btrfs_ioctl_vol_args args = {};

                /* 256M is the minimize size enforced by the btrfs kernel code when resizing (which is
                 * strange btw, as mkfs.btrfs is fine creating file systems > 109M). It will return EINVAL in
                 * that case, let's catch this error beforehand though, and report a more explanatory
                 * error. */

                if (sz < BTRFS_MINIMAL_SIZE)
                        return -ERANGE;

                sz -= sz % sfs.f_bsize;

                xsprintf(args.name, "%" PRIu64, sz);

                if (ioctl(fd, BTRFS_IOC_RESIZE, &args) < 0)
                        return -errno;

                if (ret_size)
                        *ret_size = sz;

        } else if (is_fs_type(&sfs, XFS_SB_MAGIC)) {
                xfs_fsop_geom_t geo;
                xfs_growfs_data_t d;

                if (sz < XFS_MINIMAL_SIZE)
                        return -ERANGE;

                if (ioctl(fd, XFS_IOC_FSGEOMETRY, &geo) < 0)
                        return -errno;

                d = (xfs_growfs_data_t) {
                        .imaxpct = geo.imaxpct,
                        .newblocks = sz / geo.blocksize,
                };

                if (ioctl(fd, XFS_IOC_FSGROWFSDATA, &d) < 0)
                        return -errno;

                if (ret_size)
                        *ret_size = d.newblocks * geo.blocksize;

        } else
                return -EOPNOTSUPP;

        return 0;
}

uint64_t minimal_size_by_fs_magic(statfs_f_type_t magic) {

        switch (magic) {

        case (statfs_f_type_t) EXT4_SUPER_MAGIC:
                return EXT4_MINIMAL_SIZE;

        case (statfs_f_type_t) XFS_SB_MAGIC:
                return XFS_MINIMAL_SIZE;

        case (statfs_f_type_t) BTRFS_SUPER_MAGIC:
                return  BTRFS_MINIMAL_SIZE;

        default:
                return UINT64_MAX;
        }
}

uint64_t minimal_size_by_fs_name(const char *name) {

        if (streq_ptr(name, "ext4"))
                return EXT4_MINIMAL_SIZE;

        if (streq_ptr(name, "xfs"))
                return XFS_MINIMAL_SIZE;

        if (streq_ptr(name, "btrfs"))
                return BTRFS_MINIMAL_SIZE;

        return UINT64_MAX;
}

/* Returns true for the only fs that can online shrink *and* grow */
bool fs_can_online_shrink_and_grow(statfs_f_type_t magic) {
        return magic == (statfs_f_type_t) BTRFS_SUPER_MAGIC;
}
