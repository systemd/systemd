/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "plymouth-util.h"
#include "socket-util.h"

int plymouth_build_password_packet(const char *message, char **ret_packet, size_t *ret_size) {
        size_t l, sz;
        char *packet;

        assert(message);
        assert(ret_packet);
        assert(ret_size);

        l = strlen(message);
        if (l >= UCHAR_MAX)
                return -EMSGSIZE;

        /* 3 byte header ('*', command, payload length), followed by the message and its NUL terminator. */
        sz = 3 + l + 1;

        packet = new(char, sz);
        if (!packet)
                return -ENOMEM;

        packet[0] = '*';
        packet[1] = '\x02';
        packet[2] = (uint8_t) (l + 1);
        memcpy(packet + 3, message, l + 1);

        *ret_packet = packet;
        *ret_size = sz;
        return 0;
}

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

static bool console_fallback = false;

void plymouth_set_console_fallback(bool b) {
        console_fallback = b;
}

int plymouth_show_message(const char *text) {
        _cleanup_close_ int fd = -EBADF;

        assert(text);

        /* Shows a message that asks the user to do something, e.g. to plug in or touch a security token,
         * via plymouth. If plymouth doesn't show it and the console fallback is enabled, the message is
         * written to the console instead: services that enable it log to the journal only, so the user
         * would not see the request otherwise. Returns > 0 if plymouth shows the message, in which case
         * the caller should hide it again with plymouth_hide_message() once it is obsolete. */

        if (strlen(text) < UCHAR_MAX && plymouth_send_msg(text, /* pause_spinner= */ true) >= 0)
                return 1;

        if (!console_fallback)
                return 0;

        fd = open("/dev/console", O_WRONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open /dev/console, ignoring: %m");

        if (dprintf(fd, "%s\n", text) < 0)
                return log_debug_errno(errno, "Failed to write to /dev/console, ignoring: %m");

        return 0;
}

void plymouth_hide_message(void) {
        /* In theory 'm' should hide a message, but it doesn't work (long standing issue).
         * As a workaround, sending a single NUL byte hides the previous messages. */
        (void) plymouth_send_msg("", /* pause_spinner= */ false);
}

int plymouth_hide_splash(void) {
        int r;

        r = plymouth_send_raw("H\0", 2, SOCK_NONBLOCK);
        if (r < 0)
                return log_full_errno(ERRNO_IS_NO_PLYMOUTH(r) ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to communicate with plymouth: %m");

        return 0;
}
