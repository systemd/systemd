/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "errno-util.h"
#include "log.h"
#include "ssh-util.h"

int vsock_open_or_warn(int *ret) {
        int fd = RET_NERRNO(socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd))
                log_debug_errno(fd, "AF_VSOCK is not available, ignoring: %m");
        else if (fd < 0)
                return log_error_errno(fd, "Unable to test if AF_VSOCK is available: %m");

        if (ret)
                *ret = fd;
        else
                close(fd);

        return fd >= 0;
}
