/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chattr-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "missing_syscall.h"
#include "quota-util.h"

int quotactl_devnum(int cmd, dev_t devnum, int id, void *addr) {
        _cleanup_free_ char *devnode = NULL;
        int r;

        /* Like quotactl() but takes a dev_t instead of a path to a device node, and fixes caddr_t → void*,
         * like we should, today */

        r = devname_from_devnum(S_IFBLK, devnum, &devnode);
        if (r < 0)
                return r;

        if (quotactl(cmd, devnode, id, addr) < 0)
                return -errno;

        return 0;
}

int quotactl_path(int cmd, const char *path, int id, void *addr) {
        dev_t devno;
        int r;

        /* Like quotactl() but takes a path to some fs object, and changes the backing file system. I.e. the
         * argument shouldn't be a block device but a regular file system object */

        r = get_block_device(path, &devno);
        if (r < 0)
                return r;
        if (devno == 0) /* Doesn't have a block device */
                return -ENODEV;

        return quotactl_devnum(cmd, devno, id, addr);
}

int is_proj_id_quota_supported(int fd, uint32_t proj_id, struct dqblk *req) {
        int r;

        r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, req));
        if (r == -ESRCH || ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r))
                return false;

        if (r < 0)
                return r;

        return true;
}

int set_proj_id_verify_exclusive(int fd, uint32_t proj_id) {
        int r = 0;

        /* Set to top level first because of the case where directories already exist with multiple subdirectories,
           in which case, number of inodes will be > 1 if applied recursively only */
        r = set_proj_id(fd, proj_id);
        if (r < 0)
                return r;

        /* Confirm only the current inode has the project id (in case of race conditions) */
        struct dqblk req;
        r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_GETQUOTA, PRJQUOTA), proj_id, &req));
        if (r < 0)
                return r;

        if (req.dqb_curinodes != 1)
                return false;

        r = set_proj_id_recursive(fd, proj_id);
        if (r < 0)
                return r;

        return true;
}
