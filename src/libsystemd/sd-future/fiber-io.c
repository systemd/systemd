/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/epoll.h>          /* IWYU pragma: keep */
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "errno-util.h"
#include "event-future.h"
#include "fd-util.h"
#include "io-uring-util.h"
#include "io-util.h"
#include "time-util.h"

typedef ssize_t (*FiberIOFunc)(int fd, void *args);

/* An SQE stores the buffer length in 32 bits. A count of 4 GiB is truncated to 0. The recv() then returns 0,
 * and the caller treats that as EOF. The recv() and send() syscalls transfer at most INT_MAX bytes per
 * call. Clamping the count to INT_MAX therefore only makes the transfer shorter. */
static unsigned sqe_len(size_t n) {
        return MIN(n, (size_t) INT_MAX);
}

static ssize_t fiber_io_uring_await(sd_future *io) {
        int r;

        assert(io);

        r = sd_fiber_await(io);
        if (r >= 0)
                return sd_future_result(io);

        /* An interrupted wait leaves the SQE in flight, and the kernel can complete it before it processes
         * the cancellation. Wait for the CQE and return its result. Otherwise an accepted fd leaks, and
         * data that the kernel already received is lost. */
        (void) sd_future_cancel_wait_unref(sd_future_ref(io));
        if (sd_future_result(io) == -ECANCELED)
                return r;

        /* The SQE completed, so the next suspension point reports the interruption. sd_fiber_await()
         * returns -EBUSY for a wakeup without an error, so there is nothing to report for -EBUSY. */
        if (r != -EBUSY)
                assert_se(sd_fiber_resume(sd_fiber_get_current(), r) >= 0);
        return sd_future_result(io);
}

/* Only the socket wrappers pass an SQE. A socket supports non-blocking I/O from io_uring, so the kernel
 * waits for the socket without blocking the thread. A tty doesn't: the kernel runs the write inline when poll
 * reports room, and n_tty_write() sleeps until the tty drains when the write is larger than the free room.
 * That blocks the thread of the event loop. A regular file isn't pollable, so the kernel runs its I/O in a
 * worker thread. */
static ssize_t fiber_io_operation(
                int fd,
                uint32_t events,
                FiberIOFunc func,
                void *args,
                const struct io_uring_sqe *sqe) {

        _cleanup_(nonblock_resetp) int reset_fd = -EBADF;
        int r;

        assert(fd >= 0);
        assert(func);

        if (!sd_fiber_is_running())
                return func(fd, args);

        r = sd_fiber_interrupted();
        if (r < 0)
                return r;

        sd_event *e = sd_fiber_get_event();
        assert(e);

        if (sqe) {
                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;

                /* future_new_io_uring() fails without io_uring and after sd_event_exit(). A fiber that runs
                 * its cleanup after the exit still expects I/O that can complete right away to succeed. The
                 * epoll path runs the syscall before it waits, so such I/O succeeds there. */
                if (future_new_io_uring(e, sqe, &io) >= 0) {
                        ssize_t n = fiber_io_uring_await(io);

                        /* The kernel completes a recv() or send() with MSG_DONTWAIT with -EAGAIN instead
                         * of waiting for the socket. The epoll path waits for the socket. */
                        if (n != -EAGAIN)
                                return n;
                }
        }

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;
        if (r > 0)
                reset_fd = fd;

        ssize_t n = func(fd, args);
        if (n >= 0 || !ERRNO_IS_NEG_TRANSIENT(n))
                return n;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;
        r = future_new_io(e, fd, events, &io);
        if (r < 0)
                return r;

        r = sd_fiber_await(io);
        if (r < 0)
                return r;

        r = sd_future_result(io);
        if (r < 0)
                return r;

        return func(fd, args);
}

typedef struct ReadArgs {
        void *buf;
        size_t count;
} ReadArgs;

static ssize_t read_callback(int fd, void *args) {
        ReadArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = read(fd, a->buf, a->count);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_read(int fd, void *buf, size_t count) {
        assert_return(fd >= 0, -EBADF);
        assert_return(buf || count == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLIN, read_callback, &(ReadArgs) {
                .buf = buf,
                .count = count,
        }, /* sqe= */ NULL);
}

typedef struct WriteArgs {
        const void *buf;
        size_t count;
} WriteArgs;

static ssize_t write_callback(int fd, void *args) {
        WriteArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = write(fd, a->buf, a->count);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_write(int fd, const void *buf, size_t count) {
        assert_return(fd >= 0, -EBADF);
        assert_return(buf || count == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, write_callback, &(WriteArgs) {
                .buf = buf,
                .count = count,
        }, /* sqe= */ NULL);
}

typedef struct ReadvArgs {
        const struct iovec *iov;
        int iovcnt;
} ReadvArgs;

static ssize_t readv_callback(int fd, void *args) {
        ReadvArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = readv(fd, a->iov, a->iovcnt);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_readv(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLIN, readv_callback, &(ReadvArgs) {
                .iov = iov,
                .iovcnt = iovcnt,
        }, /* sqe= */ NULL);
}

typedef struct WritevArgs {
        const struct iovec *iov;
        int iovcnt;
} WritevArgs;

static ssize_t writev_callback(int fd, void *args) {
        WritevArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = writev(fd, a->iov, a->iovcnt);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_writev(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, writev_callback, &(WritevArgs) {
                .iov = iov,
                .iovcnt = iovcnt,
        }, /* sqe= */ NULL);
}

typedef struct RecvArgs {
        void *buf;
        size_t len;
        int flags;
} RecvArgs;

static ssize_t recv_callback(int fd, void *args) {
        RecvArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = recv(fd, a->buf, a->len, a->flags);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_recv(int sockfd, void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        struct io_uring_sqe sqe = {};
        io_uring_prep_recv(&sqe, sockfd, buf, sqe_len(len), flags);

        return fiber_io_operation(sockfd, EPOLLIN, recv_callback, &(RecvArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
        }, &sqe);
}

typedef struct SendArgs {
        const void *buf;
        size_t len;
        int flags;
} SendArgs;

static ssize_t send_callback(int fd, void *args) {
        SendArgs *a = ASSERT_PTR(args);
        ssize_t n;

        /* io_uring sends with MSG_NOSIGNAL in any case. We do the same here, so that a send to a closed peer
         * fails with EPIPE on both paths instead of raising SIGPIPE on this one only. */
        n = send(fd, a->buf, a->len, a->flags | MSG_NOSIGNAL);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_send(int sockfd, const void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        struct io_uring_sqe sqe = {};
        io_uring_prep_send(&sqe, sockfd, buf, sqe_len(len), flags);

        return fiber_io_operation(sockfd, EPOLLOUT, send_callback, &(SendArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
        }, &sqe);
}

int sd_fiber_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        _cleanup_(nonblock_resetp) int reset_fd = -EBADF;
        int r;

        assert_return(sockfd >= 0, -EBADF);
        assert_return(addr, -EINVAL);

        if (!sd_fiber_is_running())
                return RET_NERRNO(connect(sockfd, addr, addrlen));

        r = sd_fiber_interrupted();
        if (r < 0)
                return r;

        sd_event *e = sd_fiber_get_event();
        assert(e);

        r = fd_nonblock(sockfd, true);
        if (r < 0)
                return r;
        if (r > 0)
                reset_fd = sockfd;

        r = RET_NERRNO(connect(sockfd, addr, addrlen));
        if (r != -EINPROGRESS)
                return r;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;
        r = future_new_io(e, sockfd, EPOLLOUT, &io);
        if (r < 0)
                return r;

        r = sd_fiber_await(io);
        if (r < 0)
                return r;

        /* future_new_io resolves with the revents mask on success; translate any positive value
         * (e.g. POLLOUT) back to the connect(2) success status. */
        r = sd_future_result(io);
        return r > 0 ? 0 : r;
}

typedef struct RecvmsgArgs {
        struct msghdr *msg;
        int flags;
} RecvmsgArgs;

static ssize_t recvmsg_callback(int fd, void *args) {
        RecvmsgArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = recvmsg(fd, a->msg, a->flags);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_recvmsg(int sockfd, struct msghdr *msg, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(msg, -EINVAL);

        struct io_uring_sqe sqe = {};
        io_uring_prep_recvmsg(&sqe, sockfd, msg, flags);

        return fiber_io_operation(sockfd, EPOLLIN, recvmsg_callback, &(RecvmsgArgs) {
                .msg = msg,
                .flags = flags,
        }, &sqe);
}

typedef struct SendmsgArgs {
        const struct msghdr *msg;
        int flags;
} SendmsgArgs;

static ssize_t sendmsg_callback(int fd, void *args) {
        SendmsgArgs *a = ASSERT_PTR(args);
        ssize_t n;

        /* See send_callback() for MSG_NOSIGNAL. */
        n = sendmsg(fd, a->msg, a->flags | MSG_NOSIGNAL);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(msg, -EINVAL);

        struct io_uring_sqe sqe = {};
        io_uring_prep_sendmsg(&sqe, sockfd, msg, flags);

        return fiber_io_operation(sockfd, EPOLLOUT, sendmsg_callback, &(SendmsgArgs) {
                .msg = msg,
                .flags = flags,
        }, &sqe);
}

ssize_t sd_fiber_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
        ssize_t n;

        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);
        assert_return(!src_addr || addrlen, -EINVAL);

        /* io_uring has no direct recvfrom prep helper, so emulate via recvmsg with a single-iovec
         * msghdr. The kernel updates msg_namelen in place; we copy it back to *addrlen below. */
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct msghdr msg = {
                .msg_name = src_addr,
                .msg_namelen = src_addr ? *addrlen : 0,
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        struct io_uring_sqe sqe = {};
        io_uring_prep_recvmsg(&sqe, sockfd, &msg, flags);

        n = fiber_io_operation(sockfd, EPOLLIN, recvmsg_callback, &(RecvmsgArgs) {
                .msg = &msg,
                .flags = flags,
        }, &sqe);
        if (n < 0)
                return n;

        if (addrlen)
                *addrlen = msg.msg_namelen;

        return n;
}

ssize_t sd_fiber_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        struct iovec iov = { .iov_base = (void *) buf, .iov_len = len };
        struct msghdr msg = {
                .msg_name = (void *) dest_addr,
                .msg_namelen = dest_addr ? addrlen : 0,
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        struct io_uring_sqe sqe = {};
        io_uring_prep_sendmsg(&sqe, sockfd, &msg, flags);

        return fiber_io_operation(sockfd, EPOLLOUT, sendmsg_callback, &(SendmsgArgs) {
                .msg = &msg,
                .flags = flags,
        }, &sqe);
}

typedef struct AcceptArgs {
        struct sockaddr *addr;
        socklen_t *addrlen;
        int flags;
} AcceptArgs;

static ssize_t accept_callback(int fd, void *args) {
        AcceptArgs *a = ASSERT_PTR(args);

        return RET_NERRNO(accept4(fd, a->addr, a->addrlen, a->flags));
}

int sd_fiber_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
        assert_return(sockfd >= 0, -EBADF);

        struct io_uring_sqe sqe = {};
        io_uring_prep_accept(&sqe, sockfd, addr, addrlen, flags);

        return fiber_io_operation(sockfd, EPOLLIN, accept_callback, &(AcceptArgs) {
                .addr = addr,
                .addrlen = addrlen,
                .flags = flags,
        }, &sqe);
}

int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask) {
        int r;

        assert_return(fds || n_fds == 0, -EINVAL);

        if (!sd_fiber_is_running())
                return RET_NERRNO(ppoll(fds, n_fds, timeout, sigmask));

        r = sd_fiber_interrupted();
        if (r < 0)
                return r;

        /* When on a fiber signals are handled via sd-event hence we should never mess around with the
         * signal mask when running on a fiber. */
        assert_return(!sigmask, -EOPNOTSUPP);

        sd_event *e = sd_fiber_get_event();
        assert(e);

        /* No fds to wait on and no timeout means there's nothing that could ever wake the fiber up,
         * since unlike raw ppoll() we cannot use signal delivery as a wakeup. Signals received while
         * the fiber is suspended are handled by sd-event via signalfd, in which case the signal handler
         * is expected to cancel the fiber via sd_future_cancel() if a wakeup is desired. */
        if (n_fds == 0 && !timeout)
                return -EINVAL;

        bool zero_timeout = timeout && timeout->tv_sec == 0 && timeout->tv_nsec == 0;

        /* Try polling with zero timeout first to see if any are immediately ready. */
        r = RET_NERRNO(ppoll(fds, n_fds, &(const struct timespec) {}, /* sigmask= */ NULL));
        if (zero_timeout || r != 0) /* Either error or some fds are ready */
                return r;

        /* Use a WAIT_ANY group: the first child (an fd readiness or the timer) to settle resolves
         * the group, which cancels its siblings on the spot. The user-supplied event mask is in
         * poll() bits (struct pollfd), so translate to epoll bits. */
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *group = NULL;
        r = sd_future_group_new(e, &group);
        if (r < 0)
                return r;

        r = sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n_fds; i++) {
                if (fds[i].fd < 0)
                        continue;

                uint32_t events = poll_events_to_epoll(fds[i].events);
                if (events == 0)
                        continue;

                r = future_group_add_io(group, fds[i].fd, events);
                if (r < 0)
                        return r;
        }

        /* A timeout that overflows usec_t saturates to USEC_INFINITY in timespec_load(); treat that
         * like "no timeout" (matches sd_fiber_sleep(USEC_INFINITY)) rather than letting
         * sd_event_add_time_relative() reject it with -EOVERFLOW — standard ppoll() would just
         * wait a very long time. */
        usec_t usec = timeout ? timespec_load(timeout) : USEC_INFINITY;

        /* If every fd was skipped (negative or empty event mask) and we'd have no timer, there's
         * nothing that could ever wake the fiber up — same situation as n_fds == 0 && !timeout,
         * just not detectable upfront. Refuse rather than suspend forever. */
        if (sd_future_group_size(group) == 0 && usec == USEC_INFINITY)
                return -EINVAL;

        if (usec != USEC_INFINITY) {
                r = future_group_add_time_relative(
                                group,
                                CLOCK_MONOTONIC,
                                usec,
                                /* accuracy= */ 1,
                                /* result= */ 0);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_await(group);
        if (r < 0 && r != -ETIME)
                return r;
        if (r >= 0) {
                r = sd_future_result(group);
                if (r < 0)
                        return r;
        }

        /* Always sweep fds with a non-blocking ppoll(): the timer and an fd readiness can resolve in
         * the same event-loop tick (or the fd can become ready between the timer firing and us being
         * scheduled), and ppoll() semantics give events precedence over the timeout in that case. */
        int n = RET_NERRNO(ppoll(fds, n_fds, &(const struct timespec) {}, /* sigmask= */ NULL));
        if (n != 0) {
                /* sd_fiber_await() returned the expired timeout of an SD_FIBER_TIMEOUT() scope and cleared
                 * it. Queue it again, so that the next suspension point returns it. Otherwise every later
                 * wait in the scope runs without a deadline. */
                if (r == -ETIME)
                        assert_se(sd_fiber_resume(sd_fiber_get_current(), r) >= 0);

                return n;
        }

        /* No fds ready. The group's result is the winning child's result: 0 means the timer
         * (created with result=0) fired; r > 0 means an IO future fired (revents mask) but the
         * readiness was already drained when we swept. Both map to "0 fds ready". */
        if (r >= 0)
                return 0;

        return r;
}
