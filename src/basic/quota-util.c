/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "quota-util.h"
#include "stat-util.h"

int quotactl_devno(int cmd, dev_t devno, int id, void *addr) {
        _cleanup_free_ char *devnode = NULL;
        int r;

        /* Like quotactl() but takes a dev_t instead of a path to a device node, and fixes caddr_t → void*,
         * like we should, today */

        r = device_path_make_major_minor(S_IFBLK, devno, &devnode);
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

        return quotactl_devno(cmd, devno, id, addr);
}
