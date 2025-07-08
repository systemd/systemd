/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chattr-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "quota-util.h"

int quotactl_fd_with_fallback(int fd, int cmd, int id, void *addr) {
        int r;

        /* Emulates quotactl_fd() on older kernels that lack it. (i.e. kernels < 5.14) */

        r = RET_NERRNO(quotactl_fd(fd, cmd, id, addr));
        if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;

        dev_t devno;
        r = get_block_device_fd(fd, &devno);
        if (r < 0)
                return r;
        if (devno == 0) /* Doesn't have a block device */
                return -ENODEV;

        _cleanup_free_ char *devnode = NULL;
        r = devname_from_devnum(S_IFBLK, devno, &devnode);
        if (r < 0)
                return r;

        return RET_NERRNO(quotactl(cmd, devnode, id, addr));
}

int quota_query_proj_id(int fd, uint32_t proj_id, struct dqblk *ret_req) {
        int r;

        assert(fd >= 0);
        assert(ret_req);

        r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, ret_req);
        if (r == -ESRCH || ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r)) {
                zero(ret_req);
                return false;
        }
        if (r < 0)
                return r;

        return true;
}

int quota_proj_id_set_recursive(int fd, uint32_t proj_id, bool verify_exclusive) {
        int r;

        assert(fd >= 0);

        /* Confirm only the current inode has the project id (in case of race conditions) */
        if (verify_exclusive) {
                /* Set to top level first because of the case where directories already exist with multiple subdirectories,
                 * in which case, number of inodes will be > 1 if applied recursively only */
                r = set_proj_id(fd, proj_id);
                if (r < 0)
                        return r;

                struct dqblk req;
                r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, &req);
                if (r < 0)
                        return r;

                if (req.dqb_curinodes == 0)
                        return -ENOTRECOVERABLE;

                if (req.dqb_curinodes != 1)
                        return false;
        }

        r = set_proj_id_recursive(fd, proj_id);
        if (r < 0)
                return r;

        return true;
}

bool quota_dqblk_is_populated(const struct dqblk *req) {
        assert(req);

        return FLAGS_SET(req->dqb_valid, QIF_BLIMITS|QIF_SPACE|QIF_ILIMITS|QIF_INODES|QIF_BTIME|QIF_ITIME) &&
                (req->dqb_bhardlimit > 0 ||
                 req->dqb_bsoftlimit > 0 ||
                 req->dqb_ihardlimit > 0 ||
                 req->dqb_isoftlimit > 0 ||
                 req->dqb_curspace > 0 ||
                 req->dqb_curinodes > 0 ||
                 req->dqb_btime > 0 ||
                 req->dqb_itime > 0);
}
