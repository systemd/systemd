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
typedef void (*FiberIOPrep)(struct io_uring_sqe *sqe, int fd, void *args);

static ssize_t fiber_io_operation(
                int fd,
                uint32_t events,
                FiberIOFunc func,
                FiberIOPrep prep,
                void *args) {

        _cleanup_(nonblock_resetp) int reset_fd = -EBADF;
        int r;

        assert(fd >= 0);
        assert(func);
        assert(prep);

        if (!sd_fiber_is_running())
                return func(fd, args);

        sd_event *e = sd_fiber_get_event();
        assert(e);

#if HAVE_LIBURING
        r = sd_event_get_io_uring_enabled(e);
        if (r < 0)
                return r;
        if (r > 0) {
                /* The kernel handles blocking semantics for the SQE itself, so we don't flip the fd
                 * to non-blocking, and the CQE result lands directly as the fiber resume value:
                 * non-negative for the byte count, -errno on failure. */
                struct io_uring_sqe *sqe;
                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;
                r = future_new_io_uring_sqe(e, &sqe, &io);
                if (r < 0)
                        return r;

                prep(sqe, fd, args);

                return sd_fiber_await(io);
        }
#endif

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

#if HAVE_LIBURING
static void read_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        ReadArgs *a = ASSERT_PTR(args);
        io_uring_prep_read(sqe, fd, a->buf, a->count, /* offset = */ (uint64_t) -1);
}
#else
#  define read_prep NULL
#endif

ssize_t sd_fiber_read(int fd, void *buf, size_t count) {
        assert_return(fd >= 0, -EBADF);
        assert_return(buf || count == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLIN, read_callback, read_prep, &(ReadArgs) {
                .buf = buf,
                .count = count,
        });
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

#if HAVE_LIBURING
static void write_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        WriteArgs *a = ASSERT_PTR(args);
        io_uring_prep_write(sqe, fd, a->buf, a->count, /* offset = */ (uint64_t) -1);
}
#else
#  define write_prep NULL
#endif

ssize_t sd_fiber_write(int fd, const void *buf, size_t count) {
        assert_return(fd >= 0, -EBADF);
        assert_return(buf || count == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, write_callback, write_prep, &(WriteArgs) {
                .buf = buf,
                .count = count,
        });
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

#if HAVE_LIBURING
static void readv_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        ReadvArgs *a = ASSERT_PTR(args);
        io_uring_prep_readv(sqe, fd, a->iov, a->iovcnt, /* offset = */ (uint64_t) -1);
}
#else
#  define readv_prep NULL
#endif

ssize_t sd_fiber_readv(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLIN, readv_callback, readv_prep, &(ReadvArgs) {
                .iov = iov,
                .iovcnt = iovcnt,
        });
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

#if HAVE_LIBURING
static void writev_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        WritevArgs *a = ASSERT_PTR(args);
        io_uring_prep_writev(sqe, fd, a->iov, a->iovcnt, /* offset = */ (uint64_t) -1);
}
#else
#  define writev_prep NULL
#endif

ssize_t sd_fiber_writev(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, writev_callback, writev_prep, &(WritevArgs) {
                .iov = iov,
                .iovcnt = iovcnt,
        });
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

#if HAVE_LIBURING
static void recv_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        RecvArgs *a = ASSERT_PTR(args);
        io_uring_prep_recv(sqe, fd, a->buf, a->len, a->flags);
}
#else
#  define recv_prep NULL
#endif

ssize_t sd_fiber_recv(int sockfd, void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLIN, recv_callback, recv_prep, &(RecvArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
        });
}

typedef struct SendArgs {
        const void *buf;
        size_t len;
        int flags;
} SendArgs;

static ssize_t send_callback(int fd, void *args) {
        SendArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = send(fd, a->buf, a->len, a->flags);
        return n >= 0 ? n : -errno;
}

#if HAVE_LIBURING
static void send_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        SendArgs *a = ASSERT_PTR(args);
        io_uring_prep_send(sqe, fd, a->buf, a->len, a->flags);
}
#else
#  define send_prep NULL
#endif

ssize_t sd_fiber_send(int sockfd, const void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLOUT, send_callback, send_prep, &(SendArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
        });
}

int sd_fiber_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        _cleanup_(nonblock_resetp) int reset_fd = -EBADF;
        int r;

        assert_return(sockfd >= 0, -EBADF);
        assert_return(addr, -EINVAL);

        if (!sd_fiber_is_running())
                return RET_NERRNO(connect(sockfd, addr, addrlen));

        sd_event *e = sd_fiber_get_event();
        assert(e);

#if HAVE_LIBURING
        r = sd_event_get_io_uring_enabled(e);
        if (r < 0)
                return r;
        if (r > 0) {
                struct io_uring_sqe *sqe;
                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;
                r = future_new_io_uring_sqe(e, &sqe, &io);
                if (r < 0)
                        return r;

                io_uring_prep_connect(sqe, sockfd, addr, addrlen);

                return sd_fiber_await(io);
        }
#endif

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

        /* future_new_io resolves with the revents mask on success; translate any positive value
         * (e.g. POLLOUT) back to the connect(2) success status. */
        r = sd_fiber_await(io);
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

#if HAVE_LIBURING
static void recvmsg_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        RecvmsgArgs *a = ASSERT_PTR(args);
        io_uring_prep_recvmsg(sqe, fd, a->msg, a->flags);
}
#else
#  define recvmsg_prep NULL
#endif

ssize_t sd_fiber_recvmsg(int sockfd, struct msghdr *msg, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(msg, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLIN, recvmsg_callback, recvmsg_prep, &(RecvmsgArgs) {
                .msg = msg,
                .flags = flags,
        });
}

typedef struct SendmsgArgs {
        const struct msghdr *msg;
        int flags;
} SendmsgArgs;

static ssize_t sendmsg_callback(int fd, void *args) {
        SendmsgArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = sendmsg(fd, a->msg, a->flags);
        return n >= 0 ? n : -errno;
}

#if HAVE_LIBURING
static void sendmsg_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        SendmsgArgs *a = ASSERT_PTR(args);
        io_uring_prep_sendmsg(sqe, fd, a->msg, a->flags);
}
#else
#  define sendmsg_prep NULL
#endif

ssize_t sd_fiber_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(msg, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLOUT, sendmsg_callback, sendmsg_prep, &(SendmsgArgs) {
                .msg = msg,
                .flags = flags,
        });
}

static ssize_t recvfrom_callback(int fd, void *args) {
        RecvmsgArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = recvmsg(fd, a->msg, a->flags);
        return n >= 0 ? n : -errno;
}

#if HAVE_LIBURING
static void recvfrom_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        RecvmsgArgs *a = ASSERT_PTR(args);
        io_uring_prep_recvmsg(sqe, fd, a->msg, a->flags);
}
#else
#  define recvfrom_prep NULL
#endif

ssize_t sd_fiber_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
        ssize_t n;

        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);
        assert_return(!src_addr || addrlen, -EINVAL);

        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct msghdr msg = {
                .msg_name = src_addr,
                .msg_namelen = src_addr ? *addrlen : 0,
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        n = fiber_io_operation(sockfd, EPOLLIN, recvfrom_callback, recvfrom_prep, &(RecvmsgArgs) {
                .msg = &msg,
                .flags = flags,
        });
        if (n < 0)
                return n;

        if (addrlen)
                *addrlen = msg.msg_namelen;

        return n;
}

static ssize_t sendto_callback(int fd, void *args) {
        SendmsgArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = sendmsg(fd, a->msg, a->flags);
        return n >= 0 ? n : -errno;
}

#if HAVE_LIBURING
static void sendto_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        SendmsgArgs *a = ASSERT_PTR(args);
        io_uring_prep_sendmsg(sqe, fd, a->msg, a->flags);
}
#else
#  define sendto_prep NULL
#endif

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

        return fiber_io_operation(sockfd, EPOLLOUT, sendto_callback, sendto_prep, &(SendmsgArgs) {
                .msg = &msg,
                .flags = flags,
        });
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

#if HAVE_LIBURING
static void accept_prep(struct io_uring_sqe *sqe, int fd, void *args) {
        AcceptArgs *a = ASSERT_PTR(args);
        io_uring_prep_accept(sqe, fd, a->addr, a->addrlen, a->flags);
}
#else
#  define accept_prep NULL
#endif

int sd_fiber_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
        assert_return(sockfd >= 0, -EBADF);

        return fiber_io_operation(sockfd, EPOLLIN, accept_callback, accept_prep, &(AcceptArgs) {
                .addr = addr,
                .addrlen = addrlen,
                .flags = flags,
        });
}

/* Unlike sd_fiber_read/write/connect/etc., this function does not submit io-uring SQEs directly: the
 * underlying future_new_io() / future_new_time_relative() already route through io_uring_prep_poll_add
 * (via sd_event_add_io and the per-clock timerfd) when io-uring is enabled on the event loop, so a
 * direct submission would just duplicate that work. */
int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask) {
        int r;

        assert_return(fds || n_fds == 0, -EINVAL);

        if (!sd_fiber_is_running())
                return RET_NERRNO(ppoll(fds, n_fds, timeout, sigmask));

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

                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *io = NULL;
                r = future_new_io(e, fds[i].fd, events, &io);
                if (r < 0)
                        return r;

                r = sd_future_group_add(group, io);
                if (r < 0)
                        return r;

                io = sd_future_unref(io);
        }

        /* A timeout that overflows usec_t saturates to USEC_INFINITY in timespec_load(); treat that
         * like "no timeout" (matches sd_fiber_sleep(USEC_INFINITY)) rather than letting
         * sd_event_add_time_relative() reject it with -EOVERFLOW — standard ppoll() would just
         * wait a very long time. */
        usec_t usec = timeout ? timespec_load(timeout) : USEC_INFINITY;

        size_t size;
        r = sd_future_group_size(group, &size);
        if (r < 0)
                return r;

        /* If every fd was skipped (negative or empty event mask) and we'd have no timer, there's
         * nothing that could ever wake the fiber up — same situation as n_fds == 0 && !timeout,
         * just not detectable upfront. Refuse rather than suspend forever. */
        if (size == 0 && usec == USEC_INFINITY)
                return -EINVAL;

        if (usec != USEC_INFINITY) {
                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *timer = NULL;
                r = future_new_time_relative(
                                e,
                                CLOCK_MONOTONIC,
                                usec,
                                /* accuracy= */ 1,
                                /* result= */ 0,
                                &timer);
                if (r < 0)
                        return r;

                r = sd_future_group_add(group, timer);
                if (r < 0)
                        return r;

                timer = sd_future_unref(timer);
        }

        r = sd_future_group_await(group);
        if (r < 0 && r != -ETIME)
                return r;

        /* Always sweep fds with a non-blocking ppoll(): the timer and an fd readiness can resolve in
         * the same event-loop tick (or the fd can become ready between the timer firing and us being
         * scheduled), and ppoll() semantics give events precedence over the timeout in that case. */
        int n = RET_NERRNO(ppoll(fds, n_fds, &(const struct timespec) {}, /* sigmask= */ NULL));
        if (n != 0)
                return n;

        /* No fds ready. The group's result is the winning child's result: 0 means the timer
         * (created with result=0) fired; r > 0 means an IO future fired (revents mask) but the
         * readiness was already drained when we swept. Both map to "0 fds ready". */
        if (r >= 0)
                return 0;

        return r;
}
