/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <sys/quota.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chattr-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "missing_syscall.h"
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

int quota_query_proj_id(int fd, uint32_t proj_id, struct dqblk *req) {
        int r;

        assert(fd >= 0);
        assert(req);

        zero(*req);

        r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, req));
        if (r == -ESRCH || ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r))
                return false;
        if (r < 0)
                return r;

        return true;
}

int quota_proj_id_set_recursive(int fd, uint32_t proj_id, bool verify_exclusive) {
        int r;

        assert(fd >= 0);

        /* Set to top level first because of the case where directories already exist with multiple subdirectories,
           in which case, number of inodes will be > 1 if applied recursively only */
        r = set_proj_id(fd, proj_id);
        if (r < 0)
                return r;

        /* Confirm only the current inode has the project id (in case of race conditions) */
        if (verify_exclusive) {
                struct dqblk req;
                r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, &req));
                if (r < 0)
                        return r;

                if (req.dqb_curinodes != 1)
                        return false;
        }

        r = set_proj_id_recursive(fd, proj_id);
        if (r < 0)
                return r;

        return true;
}
