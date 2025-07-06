/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
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
