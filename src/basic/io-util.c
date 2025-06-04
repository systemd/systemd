/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "errno-util.h"
#include "io-util.h"
#include "time-util.h"

int flush_fd(int fd) {
        int count = 0;

        /* Read from the specified file descriptor, until POLLIN is not set anymore, throwing away everything
         * read. Note that some file descriptors (notable IP sockets) will trigger POLLIN even when no data can be read
         * (due to IP packet checksum mismatches), hence this function is only safe to be non-blocking if the fd used
         * was set to non-blocking too. */

        for (;;) {
                char buf[LINE_MAX];
                ssize_t l;
                int r;

                r = fd_wait_for_event(fd, POLLIN, 0);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return count;

                l = read(fd, buf, sizeof(buf));
                if (l < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == EAGAIN)
                                return count;

                        return -errno;
                } else if (l == 0)
                        return count;

                if (l > INT_MAX-count) /* On overflow terminate */
                        return INT_MAX;

                count += (int) l;
        }
}

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll) {
        uint8_t *p = ASSERT_PTR(buf);
        ssize_t n = 0;

        assert(fd >= 0);

        /* If called with nbytes == 0, let's call read() at least once, to validate the operation */

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
                assert(k <= SSIZE_MAX - n);

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

int loop_write_full(int fd, const void *buf, size_t nbytes, usec_t timeout) {
        const uint8_t *p;
        usec_t end;
        int r;

        assert(fd >= 0);
        assert(buf || nbytes == 0);

        if (nbytes == 0) {
                static const dummy_t dummy[0];
                assert_cc(sizeof(dummy) == 0);
                p = (const void*) dummy; /* Some valid pointer, in case NULL was specified */
        } else {
                if (nbytes == SIZE_MAX)
                        nbytes = strlen(buf);
                else if (_unlikely_(nbytes > (size_t) SSIZE_MAX))
                        return -EINVAL;

                p = buf;
        }

        /* When timeout is 0 or USEC_INFINITY this is not used. But we initialize it to a sensible value. */
        end = timestamp_is_set(timeout) ? usec_add(now(CLOCK_MONOTONIC), timeout) : USEC_INFINITY;

        do {
                ssize_t k;

                k = write(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        if (errno != EAGAIN || timeout == 0)
                                return -errno;

                        usec_t wait_for;

                        if (timeout == USEC_INFINITY)
                                wait_for = USEC_INFINITY;
                        else {
                                usec_t t = now(CLOCK_MONOTONIC);
                                if (t >= end)
                                        return -ETIME;

                                wait_for = usec_sub_unsigned(end, t);
                        }

                        r = fd_wait_for_event(fd, POLLOUT, wait_for);
                        if (timeout == USEC_INFINITY || ERRNO_IS_NEG_TRANSIENT(r))
                                /* If timeout == USEC_INFINITY we knowingly ignore any return value
                                 * here, and expect that any error/EOF is reported via write() */
                                continue;
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -ETIME;
                        continue;
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
        int r;

        r = fd_wait_for_event(fd, POLLIN, 0);
        if (r <= 0)
                return r;

        return !!(r & POLLHUP);
}

int ppoll_usec_full(struct pollfd *fds, size_t n_fds, usec_t timeout, const sigset_t *ss) {
        int r;

        assert(fds || n_fds == 0);

        /* This is a wrapper around ppoll() that does primarily two things:
         *
         *  ✅ Takes a usec_t instead of a struct timespec
         *
         *  ✅ Guarantees that if an invalid fd is specified we return EBADF (i.e. converts POLLNVAL to
         *     EBADF). This is done because EBADF is a programming error usually, and hence should bubble up
         *     as error, and not be eaten up as non-error POLLNVAL event.
         *
         *  ⚠️ ⚠️ ⚠️ Note that this function does not add any special handling for EINTR. Don't forget
         *  poll()/ppoll() will return with EINTR on any received signal always, there is no automatic
         *  restarting via SA_RESTART available. Thus, typically you want to handle EINTR not as an error,
         *  but just as reason to restart things, under the assumption you use a more appropriate mechanism
         *  to handle signals, such as signalfd() or signal handlers. ⚠️ ⚠️ ⚠️
         */

        if (n_fds == 0 && timeout == 0)
                return 0;

        r = ppoll(fds, n_fds, timeout == USEC_INFINITY ? NULL : TIMESPEC_STORE(timeout), ss);
        if (r < 0)
                return -errno;
        if (r == 0)
                return 0;

        for (size_t i = 0, n = r; i < n_fds && n > 0; i++) {
                if (fds[i].revents == 0)
                        continue;
                if (fds[i].revents & POLLNVAL)
                        return -EBADF;
                n--;
        }

        return r;
}

int fd_wait_for_event(int fd, int event, usec_t timeout) {
        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };
        int r;

        /* ⚠️ ⚠️ ⚠️ Keep in mind you almost certainly want to handle -EINTR gracefully in the caller, see
         * ppoll_usec() above! ⚠️ ⚠️ ⚠️ */

        r = ppoll_usec(&pollfd, 1, timeout);
        if (r <= 0)
                return r;

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

                        if (lseek(fd, n, SEEK_CUR) < 0)
                                return -errno;

                        q += n;
                        w = q;
                } else if (n > 0)
                        q += n;
                else
                        q++;
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
