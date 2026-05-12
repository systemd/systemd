/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef quotactl_fd
extern typeof(missing_quotactl_fd) quotactl_fd;
#pragma weak quotactl_fd
int missing_quotactl_fd(int fd, int cmd, int id, void *addr) {
        if (quotactl_fd)
                return quotactl_fd(fd, cmd, id, addr);
        return syscall(__NR_quotactl_fd, fd, cmd, id, addr);
}
