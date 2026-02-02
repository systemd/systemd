/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
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

        if (connect(fd, &sa.sa, sockaddr_un_len(&sa.un)) < 0)
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

int plymouth_send_msg(const char *text, bool pause_spinner) {
        _cleanup_free_ char *plymouth_message = NULL;
        int c, r;

        assert(text);
        assert(strlen(text) < UCHAR_MAX);

        c = asprintf(&plymouth_message,
                     "M\x02%c%s%c"
                     "%c%c", /* pause/resume spinner */
                     (int) strlen(text) + 1, text, '\x00',
                     pause_spinner ? 'A' : 'a', '\x00');
        if (c < 0)
                return log_oom();

        r = plymouth_send_raw(plymouth_message, c, SOCK_NONBLOCK);
        if (r < 0)
                return log_full_errno(ERRNO_IS_NO_PLYMOUTH(r) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to communicate with plymouth, ignoring: %m");

        return 0;
}

int plymouth_hide_splash(void) {
        int r;

        r = plymouth_send_raw("H\0", 2, SOCK_NONBLOCK);
        if (r < 0)
                return log_full_errno(ERRNO_IS_NO_PLYMOUTH(r) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to communicate with plymouth: %m");

        return 0;
}
