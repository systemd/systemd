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

#include <poll.h>
#include <unistd.h>

#include "io-util.h"

int flush_fd(int fd) {
        struct pollfd pollfd = {
                .fd = fd,
                .events = POLLIN,
        };

        for (;;) {
                char buf[LINE_MAX];
                ssize_t l;
                int r;

                r = poll(&pollfd, 1, 0);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;

                } else if (r == 0)
                        return 0;

                l = read(fd, buf, sizeof(buf));
                if (l < 0) {

                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN)
                                return 0;

                        return -errno;
                } else if (l == 0)
                        return 0;
        }
}

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll) {
        uint8_t *p = buf;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        /* If called with nbytes == 0, let's call read() at least
         * once, to validate the operation */

        if (nbytes > (size_t) SSIZE_MAX)
                return -EINVAL;

        do {
                ssize_t k;

                k = read(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN && do_poll) {

                                /* We knowingly ignore any return value here,
                                 * and expect that any error/EOF is reported
                                 * via read() */

                                (void) fd_wait_for_event(fd, POLLIN, USEC_INFINITY);
                                continue;
                        }

                        return n > 0 ? n : -errno;
                }

                if (k == 0)
                        return n;

                assert((size_t) k <= nbytes);

                p += k;
                nbytes -= k;
                n += k;
        } while (nbytes > 0);

        return n;
}

int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll) {
        ssize_t n;

        n = loop_read(fd, buf, nbytes, do_poll);
        if (n < 0)
                return (int) n;
        if ((size_t) n != nbytes)
                return -EIO;

        return 0;
}

int loop_write(int fd, const void *buf, size_t nbytes, bool do_poll) {
        const uint8_t *p = buf;

        assert(fd >= 0);
        assert(buf);

        if (nbytes > (size_t) SSIZE_MAX)
                return -EINVAL;

        do {
                ssize_t k;

                k = write(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno == EAGAIN && do_poll) {
                                /* We knowingly ignore any return value here,
                                 * and expect that any error/EOF is reported
                                 * via write() */

                                (void) fd_wait_for_event(fd, POLLOUT, USEC_INFINITY);
                                continue;
                        }

                        return -errno;
                }

                if (_unlikely_(nbytes > 0 && k == 0)) /* Can't really happen */
                        return -EIO;

                assert((size_t) k <= nbytes);

                p += k;
                nbytes -= k;
        } while (nbytes > 0);

        return 0;
}

int pipe_eof(int fd) {
        struct pollfd pollfd = {
                .fd = fd,
                .events = POLLIN|POLLHUP,
        };

        int r;

        r = poll(&pollfd, 1, 0);
        if (r < 0)
                return -errno;

        if (r == 0)
                return 0;

        return pollfd.revents & POLLHUP;
}

int fd_wait_for_event(int fd, int event, usec_t t) {

        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };

        struct timespec ts;
        int r;

        r = ppoll(&pollfd, 1, t == USEC_INFINITY ? NULL : timespec_store(&ts, t), NULL);
        if (r < 0)
                return -errno;

        if (r == 0)
                return 0;

        return pollfd.revents;
}

static size_t nul_length(const uint8_t *p, size_t sz) {
        size_t n = 0;

        while (sz > 0) {
                if (*p != 0)
                        break;

                n++;
                p++;
                sz--;
        }

        return n;
}

ssize_t sparse_write(int fd, const void *p, size_t sz, size_t run_length) {
        const uint8_t *q, *w, *e;
        ssize_t l;

        q = w = p;
        e = q + sz;
        while (q < e) {
                size_t n;

                n = nul_length(q, e - q);

                /* If there are more than the specified run length of
                 * NUL bytes, or if this is the beginning or the end
                 * of the buffer, then seek instead of write */
                if ((n > run_length) ||
                    (n > 0 && q == p) ||
                    (n > 0 && q + n >= e)) {
                        if (q > w) {
                                l = write(fd, w, q - w);
                                if (l < 0)
                                        return -errno;
                                if (l != q -w)
                                        return -EIO;
                        }

                        if (lseek(fd, n, SEEK_CUR) == (off_t) -1)
                                return -errno;

                        q += n;
                        w = q;
                } else if (n > 0)
                        q += n;
                else
                        q ++;
        }

        if (q > w) {
                l = write(fd, w, q - w);
                if (l < 0)
                        return -errno;
                if (l != q - w)
                        return -EIO;
        }

        return q - (const uint8_t*) p;
}
