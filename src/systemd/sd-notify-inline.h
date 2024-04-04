/* SPDX-License-Identifier: MIT-0 */
#ifndef foosdnotifyinlinehfoo
#define foosdnotifyinlinehfoo

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* setenv/unsetenv are defined conditionally. Provide this function only if they are available. */
#if _POSIX_C_SOURCE >= 200112L || _BSD_SOURCE
static __inline__ int sd_notify_inline(int unset_environment, const char *message) {
        union sockaddr_union {
                struct sockaddr sa;
                struct sockaddr_un sun;
        } socket_addr;
        size_t path_length, message_length;
        ssize_t written;
        int r, fd = -1;
        const char *socket_path;

        /* Save the socket path, and always the environment variable. */
        socket_path = getenv("NOTIFY_SOCKET");
        if (unset_environment)
                unsetenv("NOTIFY_SOCKET");

        /* Verify arguments */
        if (!message)
                return -EINVAL;
        message_length = strlen(message);
        if (message_length == 0)
                return -EINVAL;

        if (!socket_path)
                return 0; /* Not running under systemd? Nothing to do */

        /* Only AF_UNIX is supported, with path or abstract sockets */
        if (socket_path[0] != '/' && socket_path[0] != '@')
                return -EAFNOSUPPORT;

        path_length = strlen(socket_path);
        /* Ensure there is room for NUL byte */
        if (path_length >= sizeof(socket_addr.sun.sun_path))
                return -E2BIG;

        socket_addr.sun.sun_family = AF_UNIX;
        memcpy(socket_addr.sun.sun_path, socket_path, path_length);

        /* Support for abstract socket */
        if (socket_addr.sun.sun_path[0] == '@')
                socket_addr.sun.sun_path[0] = 0;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0) {
                r = -errno;
                goto cleanup;
        }

        written = write(fd, message, message_length);
        r = (written == (ssize_t) message_length) ? 1 : (written < 0) ? -errno : -EPROTO;
 cleanup:
        close(fd);
        return r; /* Notified or negative error! */
}

/* vasprintf is defined conditionally. Provide this function only if it is available. */
#ifdef _GNU_SOURCE
static __inline__ int sd_notifyf_inline(int unset_environment, const char *format, ...) {
        char *p;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0 || !p)
                        return -ENOMEM;
        }

        r = sd_notify_inline(unset_environment, p);
        free(p);
        return r;
}
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
