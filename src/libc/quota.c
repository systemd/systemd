/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/quota.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !HAVE_QUOTACTL_FD
int missing_quotactl_fd(int fd, int cmd, int id, void *addr) {
        return syscall(__NR_quotactl_fd, fd, cmd, id, addr);
}
#endif
