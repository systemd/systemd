/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>

#include "sd-journal.h"
#include "util.h"
#include "socket-util.h"

/* We open a single fd, and we'll share it with the current process,
 * all its threads, and all its subprocesses. This means we need to
 * initialize it atomically, and need to operate on it atomically
 * never assuming we are the only user */

static int journal_fd(void) {
        int fd;
        static int fd_plus_one = 0;

retry:
        if (fd_plus_one > 0)
                return fd_plus_one - 1;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (!__sync_bool_compare_and_swap(&fd_plus_one, 0, fd+1)) {
                close_nointr_nofail(fd);
                goto retry;
        }

        return fd;
}

_public_ int sd_journal_print(int priority, const char *format, ...) {
        int r;
        va_list ap;

        va_start(ap, format);
        r = sd_journal_printv(priority, format, ap);
        va_end(ap);

        return r;
}

_public_ int sd_journal_printv(int priority, const char *format, va_list ap) {
        char buffer[8 + LINE_MAX], p[11];
        struct iovec iov[2];

        if (priority < 0 || priority > 7)
                return -EINVAL;

        if (!format)
                return -EINVAL;

        snprintf(p, sizeof(p), "PRIORITY=%i", priority & LOG_PRIMASK);
        char_array_0(p);

        memcpy(buffer, "MESSAGE=", 8);
        vsnprintf(buffer+8, sizeof(buffer) - 8, format, ap);
        char_array_0(buffer);

        zero(iov);
        IOVEC_SET_STRING(iov[0], buffer);
        IOVEC_SET_STRING(iov[1], p);

        return sd_journal_sendv(iov, 2);
}

_public_ int sd_journal_send(const char *format, ...) {
        int r, n = 0, i = 0, j;
        va_list ap;
        struct iovec *iov = NULL;

        va_start(ap, format);
        while (format) {
                struct iovec *c;
                char *buffer;

                if (i >= n) {
                        n = MAX(i*2, 4);
                        c = realloc(iov, n * sizeof(struct iovec));
                        if (!c) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        iov = c;
                }

                if (vasprintf(&buffer, format, ap) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }

                IOVEC_SET_STRING(iov[i++], buffer);

                format = va_arg(ap, char *);
        }
        va_end(ap);

        r = sd_journal_sendv(iov, i);

fail:
        for (j = 0; j < i; j++)
                free(iov[j].iov_base);

        free(iov);

        return r;
}

_public_ int sd_journal_sendv(const struct iovec *iov, int n) {
        int fd;
        struct iovec *w;
        uint64_t *l;
        int i, j = 0;
        struct msghdr mh;
        struct sockaddr_un sa;

        if (!iov || n <= 0)
                return -EINVAL;

        w = alloca(sizeof(struct iovec) * n * 5);
        l = alloca(sizeof(uint64_t) * n);

        for (i = 0; i < n; i++) {
                char *c, *nl;

                if (!iov[i].iov_base ||
                    iov[i].iov_len <= 1)
                        return -EINVAL;

                c = memchr(iov[i].iov_base, '=', iov[i].iov_len);
                if (!c || c == iov[i].iov_base)
                        return -EINVAL;

                nl = memchr(iov[i].iov_base, '\n', iov[i].iov_len);
                if (nl) {
                        if (nl < c)
                                return -EINVAL;

                        /* Already includes a newline? Bummer, then
                         * let's write the variable name, then a
                         * newline, then the size (64bit LE), followed
                         * by the data and a final newline */

                        w[j].iov_base = iov[i].iov_base;
                        w[j].iov_len = c - (char*) iov[i].iov_base;
                        j++;

                        IOVEC_SET_STRING(w[j++], "\n");

                        l[i] = htole64(iov[i].iov_len - (c - (char*) iov[i].iov_base) - 1);
                        w[j].iov_base = &l[i];
                        w[j].iov_len = sizeof(uint64_t);
                        j++;

                        w[j].iov_base = c + 1;
                        w[j].iov_len = iov[i].iov_len - (c - (char*) iov[i].iov_base) - 1;
                        j++;

                } else
                        /* Nothing special? Then just add the line and
                         * append a newline */
                        w[j++] = iov[i];

                IOVEC_SET_STRING(w[j++], "\n");
        }

        fd = journal_fd();
        if (fd < 0)
                return fd;

        zero(sa);
        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path,"/run/systemd/journal/socket", sizeof(sa.sun_path));

        zero(mh);
        mh.msg_name = &sa;
        mh.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(sa.sun_path);
        mh.msg_iov = w;
        mh.msg_iovlen = j;

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

_public_ int sd_journal_stream_fd(const char *tag, int priority, int priority_prefix) {
        union sockaddr_union sa;
        int fd;
        char *header;
        size_t l;
        ssize_t r;

        if (priority < 0 || priority > 7)
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/run/systemd/journal/stdout", sizeof(sa.un.sun_path));

        r = connect(fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
        if (r < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        if (!tag)
                tag = "";

        l = strlen(tag);
        header = alloca(l + 1 + 2 + 2 + 2 + 2 + 2);

        memcpy(header, tag, l);
        header[l++] = '\n';
        header[l++] = '0' + priority;
        header[l++] = '\n';
        header[l++] = '0' + !!priority_prefix;
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';
        header[l++] = '0';
        header[l++] = '\n';

        r = loop_write(fd, header, l, false);
        if (r < 0) {
                close_nointr_nofail(fd);
                return (int) r;
        }

        if ((size_t) r != l) {
                close_nointr_nofail(fd);
                return -errno;
        }

        return fd;
}
