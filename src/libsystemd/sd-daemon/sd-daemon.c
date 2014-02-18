/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <mqueue.h>

#include "util.h"
#include "sd-daemon.h"

_public_ int sd_listen_fds(int unset_environment) {
        int r, fd;
        const char *e;
        char *p = NULL;
        unsigned long l;

        e = getenv("LISTEN_PID");
        if (!e) {
                r = 0;
                goto finish;
        }

        errno = 0;
        l = strtoul(e, &p, 10);

        if (errno > 0) {
                r = -errno;
                goto finish;
        }

        if (!p || p == e || *p || l <= 0) {
                r = -EINVAL;
                goto finish;
        }

        /* Is this for us? */
        if (getpid() != (pid_t) l) {
                r = 0;
                goto finish;
        }

        e = getenv("LISTEN_FDS");
        if (!e) {
                r = 0;
                goto finish;
        }

        errno = 0;
        l = strtoul(e, &p, 10);

        if (errno > 0) {
                r = -errno;
                goto finish;
        }

        if (!p || p == e || *p) {
                r = -EINVAL;
                goto finish;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + (int) l; fd ++) {
                int flags;

                flags = fcntl(fd, F_GETFD);
                if (flags < 0) {
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
}

_public_ int sd_is_fifo(int fd, const char *path) {
        struct stat st_fd;

        if (fd < 0)
                return -EINVAL;

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISFIFO(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

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

_public_ int sd_is_special(int fd, const char *path) {
        struct stat st_fd;

        if (fd < 0)
                return -EINVAL;

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISREG(st_fd.st_mode) && !S_ISCHR(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                if (stat(path, &st_path) < 0) {

                        if (errno == ENOENT || errno == ENOTDIR)
                                return 0;

                        return -errno;
                }

                if (S_ISREG(st_fd.st_mode) && S_ISREG(st_path.st_mode))
                        return
                                st_path.st_dev == st_fd.st_dev &&
                                st_path.st_ino == st_fd.st_ino;
                else if (S_ISCHR(st_fd.st_mode) && S_ISCHR(st_path.st_mode))
                        return st_path.st_rdev == st_fd.st_rdev;
                else
                        return 0;
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

_public_ int sd_is_socket(int fd, int family, int type, int listening) {
        int r;

        if (family < 0)
                return -EINVAL;

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (family > 0) {
                union sockaddr_union sockaddr = {};
                socklen_t l = sizeof(sockaddr);

                if (getsockname(fd, &sockaddr.sa, &l) < 0)
                        return -errno;

                if (l < sizeof(sa_family_t))
                        return -EINVAL;

                return sockaddr.sa.sa_family == family;
        }

        return 1;
}

_public_ int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
        union sockaddr_union sockaddr = {};
        socklen_t l = sizeof(sockaddr);
        int r;

        if (family != 0 && family != AF_INET && family != AF_INET6)
                return -EINVAL;

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

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

_public_ int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
        union sockaddr_union sockaddr = {};
        socklen_t l = sizeof(sockaddr);
        int r;

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (sockaddr.sa.sa_family != AF_UNIX)
                return 0;

        if (path) {
                if (length == 0)
                        length = strlen(path);

                if (length == 0)
                        /* Unnamed socket */
                        return l == offsetof(struct sockaddr_un, sun_path);

                if (path[0])
                        /* Normal path socket */
                        return
                                (l >= offsetof(struct sockaddr_un, sun_path) + length + 1) &&
                                memcmp(path, sockaddr.un.sun_path, length+1) == 0;
                else
                        /* Abstract namespace socket */
                        return
                                (l == offsetof(struct sockaddr_un, sun_path) + length) &&
                                memcmp(path, sockaddr.un.sun_path, length) == 0;
        }

        return 1;
}

_public_ int sd_is_mq(int fd, const char *path) {
        struct mq_attr attr;

        if (fd < 0)
                return -EINVAL;

        if (mq_getattr(fd, &attr) < 0)
                return -errno;

        if (path) {
                char fpath[PATH_MAX];
                struct stat a, b;

                if (path[0] != '/')
                        return -EINVAL;

                if (fstat(fd, &a) < 0)
                        return -errno;

                strncpy(stpcpy(fpath, "/dev/mqueue"), path, sizeof(fpath) - 12);
                fpath[sizeof(fpath)-1] = 0;

                if (stat(fpath, &b) < 0)
                        return -errno;

                if (a.st_dev != b.st_dev ||
                    a.st_ino != b.st_ino)
                        return 0;
        }

        return 1;
}

_public_ int sd_notify(int unset_environment, const char *state) {
        int fd = -1, r;
        struct msghdr msghdr;
        struct iovec iovec;
        union sockaddr_union sockaddr;
        const char *e;

        if (!state) {
                r = -EINVAL;
                goto finish;
        }

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        /* Must be an abstract socket, or an absolute path */
        if ((e[0] != '@' && e[0] != '/') || e[1] == 0) {
                r = -EINVAL;
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        memzero(&sockaddr, sizeof(sockaddr));
        sockaddr.sa.sa_family = AF_UNIX;
        strncpy(sockaddr.un.sun_path, e, sizeof(sockaddr.un.sun_path));

        if (sockaddr.un.sun_path[0] == '@')
                sockaddr.un.sun_path[0] = 0;

        memzero(&iovec, sizeof(iovec));
        iovec.iov_base = (char*) state;
        iovec.iov_len = strlen(state);

        memzero(&msghdr, sizeof(msghdr));
        msghdr.msg_name = &sockaddr;
        msghdr.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(e);

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
}

_public_ int sd_notifyf(int unset_environment, const char *format, ...) {
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
}

_public_ int sd_booted(void) {
        struct stat st;

        /* We test whether the runtime unit file directory has been
         * created. This takes place in mount-setup.c, so is
         * guaranteed to happen very early during boot. */

        if (lstat("/run/systemd/system/", &st) < 0)
                return 0;

        return !!S_ISDIR(st.st_mode);
}

_public_ int sd_watchdog_enabled(int unset_environment, uint64_t *usec) {
        unsigned long long ll;
        unsigned long l;
        const char *e;
        char *p = NULL;
        int r;

        e = getenv("WATCHDOG_PID");
        if (!e) {
                r = 0;
                goto finish;
        }

        errno = 0;
        l = strtoul(e, &p, 10);
        if (errno > 0) {
                r = -errno;
                goto finish;
        }
        if (!p || p == e || *p || l <= 0) {
                r = -EINVAL;
                goto finish;
        }

        /* Is this for us? */
        if (getpid() != (pid_t) l) {
                r = 0;
                goto finish;
        }

        e = getenv("WATCHDOG_USEC");
        if (!e) {
                r = -EINVAL;
                goto finish;
        }

        errno = 0;
        ll = strtoull(e, &p, 10);
        if (errno > 0) {
                r = -errno;
                goto finish;
        }
        if (!p || p == e || *p || l <= 0) {
                r = -EINVAL;
                goto finish;
        }

        if (usec)
                *usec = ll;

        r = 1;

finish:
        if (unset_environment) {
                unsetenv("WATCHDOG_PID");
                unsetenv("WATCHDOG_USEC");
        }

        return r;
}
