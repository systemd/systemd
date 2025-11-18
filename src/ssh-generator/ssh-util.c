/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "socket-util.h"
#include "ssh-util.h"

int vsock_open_or_warn(int *ret) {
        _cleanup_close_ int fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_debug_errno(errno, "AF_VSOCK is not available, ignoring: %m");
                        return 0;
                }

                return log_error_errno(errno, "Unable to test if AF_VSOCK is available: %m");
        }

        if (ret)
                *ret = TAKE_FD(fd);
        return 1;
}

int vsock_get_local_cid_or_warn(unsigned *ret) {
        int r;

        r = vsock_get_local_cid(ret);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                log_debug_errno(r, "/dev/vsock is not available (even though AF_VSOCK is), ignoring: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to query local AF_VSOCK CID: %m");
        return 1;
}
