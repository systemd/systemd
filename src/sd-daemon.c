/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  Copyright 2010 Lennart Poettering

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "sd-daemon.h"

int sd_listen_fds(int unset_environment) {

#if defined(DISABLE_SYSTEMD) || !defined(__linux__)
        return 0;
#else
        int r, fd;
        const char *e;
        char *p = NULL;
        unsigned long l;

        if (!(e = getenv("LISTEN_PID"))) {
                r = 0;
                goto finish;
        }

        errno = 0;
        l = strtoul(e, &p, 10);

        if (errno != 0) {
                r = -errno;
                goto finish;
        }

        if (!p || *p || l <= 0) {
                r = -EINVAL;
                goto finish;
        }

        /* Is this for us? */
        if (getpid() != (pid_t) l) {
                r = 0;
                goto finish;
        }

        if (!(e = getenv("LISTEN_FDS"))) {
                r = 0;
                goto finish;
        }

        errno = 0;
        l = strtoul(e, &p, 10);

        if (errno != 0) {
                r = -errno;
                goto finish;
        }

        if (!p || *p) {
                r = -EINVAL;
                goto finish;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + (int) l; fd ++) {
                int flags;

                if ((flags = fcntl(fd, F_GETFD)) < 0) {
                        r = -errno;
                        goto finish;
                }

                if (flags & FD_CLOEXEC)
                        continue;

                if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        r = (int) l;

finish:
        if (unset_environment) {
                unsetenv("LISTEN_PID");
                unsetenv("LISTEN_FDS");
        }

        return r;
#endif
}

int sd_is_fifo(int fd, const char *path) {
        struct stat st_fd;

        if (fd < 0)
                return -EINVAL;

        memset(&st_fd, 0, sizeof(st_fd));
        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISFIFO(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                memset(&st_path, 0, sizeof(st_path));
                if (stat(path, &st_path) < 0) {

                        if (errno == ENOENT || errno == ENOTDIR)
                                return 0;

                        return -errno;
                }

                return
                        st_path.st_dev == st_fd.st_dev &&
                        st_path.st_ino == st_fd.st_ino;
        }

        return 1;
}

static int sd_is_socket_internal(int fd, int type, int listening) {
        struct stat st_fd;

        if (fd < 0 || type < 0)
                return -EINVAL;

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISSOCK(st_fd.st_mode))
                return 0;

        if (type != 0) {
                int other_type = 0;
                socklen_t l = sizeof(other_type);

                if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &other_type, &l) < 0)
                        return -errno;

                if (l != sizeof(other_type))
                        return -EINVAL;

                if (other_type != type)
                        return 0;
        }

        if (listening >= 0) {
                int accepting = 0;
                socklen_t l = sizeof(accepting);

                if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &l) < 0)
                        return -errno;

                if (l != sizeof(accepting))
                        return -EINVAL;

                if (!accepting != !listening)
                        return 0;
        }

        return 1;
}

union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_storage storage;
};

int sd_is_socket(int fd, int family, int type, int listening) {
        int r;

        if (family < 0)
                return -EINVAL;

        if ((r = sd_is_socket_internal(fd, type, listening)) <= 0)
                return r;

        if (family > 0) {
                union sockaddr_union sockaddr;
                socklen_t l;

                memset(&sockaddr, 0, sizeof(sockaddr));
                l = sizeof(sockaddr);

                if (getsockname(fd, &sockaddr.sa, &l) < 0)
                        return -errno;

                if (l < sizeof(sa_family_t))
                        return -EINVAL;

                return sockaddr.sa.sa_family == family;
        }

        return 1;
}

int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
        union sockaddr_union sockaddr;
        socklen_t l;
        int r;

        if (family != 0 && family != AF_INET && family != AF_INET6)
                return -EINVAL;

        if ((r = sd_is_socket_internal(fd, type, listening)) <= 0)
                return r;

        memset(&sockaddr, 0, sizeof(sockaddr));
        l = sizeof(sockaddr);

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (sockaddr.sa.sa_family != AF_INET &&
            sockaddr.sa.sa_family != AF_INET6)
                return 0;

        if (family > 0)
                if (sockaddr.sa.sa_family != family)
                        return 0;

        if (port > 0) {
                if (sockaddr.sa.sa_family == AF_INET) {
                        if (l < sizeof(struct sockaddr_in))
                                return -EINVAL;

                        return htons(port) == sockaddr.in4.sin_port;
                } else {
                        if (l < sizeof(struct sockaddr_in6))
                                return -EINVAL;

                        return htons(port) == sockaddr.in6.sin6_port;
                }
        }

        return 1;
}

int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
        union sockaddr_union sockaddr;
        socklen_t l;
        int r;

        if ((r = sd_is_socket_internal(fd, type, listening)) <= 0)
                return r;

        memset(&sockaddr, 0, sizeof(sockaddr));
        l = sizeof(sockaddr);

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (sockaddr.sa.sa_family != AF_UNIX)
                return 0;

        if (path) {
                if (length <= 0)
                        length = strlen(path);

                if (length <= 0)
                        /* Unnamed socket */
                        return l == sizeof(sa_family_t);

                if (path[0])
                        /* Normal path socket */
                        return
                                (l >= sizeof(sa_family_t) + length + 1) &&
                                memcmp(path, sockaddr.un.sun_path, length+1) == 0;
                else
                        /* Abstract namespace socket */
                        return
                                (l == sizeof(sa_family_t) + length) &&
                                memcmp(path, sockaddr.un.sun_path, length) == 0;
        }

        return 1;
}

int sd_notify(int unset_environment, const char *state) {
#if defined(DISABLE_SYSTEMD) || !defined(__linux__) || !defined(SOCK_CLOEXEC)
        return 0;
#else
        int fd = -1, r;
        struct msghdr msghdr;
        struct iovec iovec;
        union sockaddr_union sockaddr;
        const char *e;

        if (!state) {
                r = -EINVAL;
                goto finish;
        }

        if (!(e = getenv("NOTIFY_SOCKET")))
                return 0;

        /* Must be an abstract socket, or an absolute path */
        if ((e[0] != '@' && e[0] != '/') || e[1] == 0) {
                r = -EINVAL;
                goto finish;
        }

        if ((fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
                r = -errno;
                goto finish;
        }

        memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.sa.sa_family = AF_UNIX;
        strncpy(sockaddr.un.sun_path, e, sizeof(sockaddr.un.sun_path));

        if (sockaddr.un.sun_path[0] == '@')
                sockaddr.un.sun_path[0] = 0;

        memset(&iovec, 0, sizeof(iovec));
        iovec.iov_base = (char*) state;
        iovec.iov_len = strlen(state);

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_name = &sockaddr;
        msghdr.msg_namelen = sizeof(sa_family_t) + strlen(e);

        if (msghdr.msg_namelen > sizeof(struct sockaddr_un))
                msghdr.msg_namelen = sizeof(struct sockaddr_un);

        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0) {
                r = -errno;
                goto finish;
        }

        r = 1;

finish:
        if (unset_environment)
                unsetenv("NOTIFY_SOCKET");

        if (fd >= 0)
                close(fd);

        return r;
#endif
}

int sd_notifyf(int unset_environment, const char *format, ...) {
#if defined(DISABLE_SYSTEMD) || !defined(__linux__)
        return 0;
#else
        va_list ap;
        char *p = NULL;
        int r;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0 || !p)
                return -ENOMEM;

        r = sd_notify(unset_environment, p);
        free(p);

        return r;
#endif
}

int sd_booted(void) {
#if defined(DISABLE_SYSTEMD) || !defined(__linux__)
        return 0;
#else

        struct stat a, b;

        /* We simply test whether the systemd cgroup hierarchy is
         * mounted */

        if (lstat("/sys/fs/cgroup", &a) < 0)
                return 0;

        if (lstat("/sys/fs/cgroup/systemd", &b) < 0)
                return 0;

        return a.st_dev != b.st_dev;
#endif
}
