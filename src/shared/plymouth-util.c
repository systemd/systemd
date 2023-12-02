/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "io-util.h"
#include "plymouth-util.h"
#include "socket-util.h"

int plymouth_connect(int flags) {
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "\0/org/freedesktop/plymouthd",
        };
        _cleanup_close_ int fd = -EBADF;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|flags, 0);
        if (fd < 0)
                return -errno;

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

int plymouth_send_raw(const void *raw, size_t size, int flags) {
        _cleanup_close_ int fd = -EBADF;

        fd = plymouth_connect(flags);
        if (fd < 0)
                return fd;

        return loop_write(fd, raw, size);
}
