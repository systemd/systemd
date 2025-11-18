/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "ssh-util.h"

int vsock_open_or_warn(int *ret) {
        _cleanup_close_ int fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        log_debug_errno(errno, "AF_VSOCK is not available, ignoring: %m");
                else
                        return log_error_errno(errno, "Unable to test if AF_VSOCK is available: %m");
        }

        if (ret)
                *ret = TAKE_FD(fd);
        return fd >= 0;
}
