/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/epoll.h>          /* IWYU pragma: keep */
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-future.h"
#include "fd-util.h"
#include "io-util.h"
#include "time-util.h"

typedef ssize_t (*FiberIOFunc)(int fd, void *args);

static ssize_t fiber_io_operation(
                int fd,
                uint32_t events,
                FiberIOFunc func,
                void *args) {
        _cleanup_(nonblock_resetp) int reset_fd = -EBADF;
        int r;

        assert(fd >= 0);
        assert(func);

        if (!sd_fiber_is_running())
                return func(fd, args);

        sd_event *e = sd_fiber_get_event();
        assert(e);

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

        r = sd_fiber_suspend();
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

ssize_t sd_fiber_write(int fd, const void *buf, size_t count) {
        assert_return(fd >= 0, -EBADF);
        assert_return(buf || count == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, write_callback, &(WriteArgs) {
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

ssize_t sd_fiber_readv(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLIN, readv_callback, &(ReadvArgs) {
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

ssize_t sd_fiber_writev(int fd, const struct iovec *iov, int iovcnt) {
        assert_return(fd >= 0, -EBADF);
        assert_return(iov || iovcnt == 0, -EINVAL);

        return fiber_io_operation(fd, EPOLLOUT, writev_callback, &(WritevArgs) {
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

ssize_t sd_fiber_recv(int sockfd, void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLIN, recv_callback, &(RecvArgs) {
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

ssize_t sd_fiber_send(int sockfd, const void *buf, size_t len, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(buf || len == 0, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLOUT, send_callback, &(SendArgs) {
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
        r = sd_fiber_suspend();
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

        return fiber_io_operation(sockfd, EPOLLIN, recvmsg_callback, &(RecvmsgArgs) {
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

ssize_t sd_fiber_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
        assert_return(sockfd >= 0, -EBADF);
        assert_return(msg, -EINVAL);

        return fiber_io_operation(sockfd, EPOLLOUT, sendmsg_callback, &(SendmsgArgs) {
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

        n = fiber_io_operation(sockfd, EPOLLIN, recvfrom_callback, &(RecvfromArgs) {
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

        return fiber_io_operation(sockfd, EPOLLOUT, sendto_callback, &(SendtoArgs) {
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

int sd_fiber_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
        assert_return(sockfd >= 0, -EBADF);

        return fiber_io_operation(sockfd, EPOLLIN, accept_callback, &(AcceptArgs) {
                .addr = addr,
                .addrlen = addrlen,
                .flags = flags,
        });
}

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

        sd_future **futures = NULL;
        CLEANUP_ARRAY(futures, n_fds, sd_future_cancel_wait_unref_array);

        futures = new0(sd_future*, n_fds);
        if (!futures)
                return -ENOMEM;

        /* Set up I/O event sources for all valid fds. POLL* and EPOLL* share their bit values (see
         * EPOLL_POLL_COMMON_MASK in io-util.h), so we can pass the user-supplied event mask through
         * to either backend without translation. */
        for (size_t i = 0; i < n_fds; i++) {
                if (fds[i].fd < 0)
                        continue;

                uint32_t events = fds[i].events & EPOLL_POLL_COMMON_MASK;
                if (events == 0)
                        continue;

                r = future_new_io(e, fds[i].fd, events, &futures[i]);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *timer = NULL;
        if (timeout) {
                r = future_new_time_relative(
                                e,
                                CLOCK_MONOTONIC,
                                timespec_load(timeout),
                                /* accuracy= */ 1,
                                /* result= */ 0,
                                &timer);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_suspend();
        if (r < 0 && r != -ETIME)
                return r;

        /* If our own timer fired, we should return 0 to match ppoll() semantics. */
        if (timer && sd_future_state(timer) == SD_FUTURE_RESOLVED)
                return 0;

        /* If another timeout fired, return ETIME instead. */
        if (r < 0)
                return r;

        /* Single-fd fast path: read the resolved revents off our future directly. The multi-fd path
         * still needs ppoll(0) because sd_event_dispatch fires one source per iteration — the fiber
         * resumes after the first future completes, with the others potentially still pending despite
         * their fds being ready in the kernel. */
        if (n_fds == 1 && futures[0] && sd_future_state(futures[0]) == SD_FUTURE_RESOLVED) {
                int res = sd_future_result(futures[0]);
                fds[0].revents = res > 0 ? (short) res : 0;
                return fds[0].revents != 0 ? 1 : 0;
        }

        return RET_NERRNO(ppoll(fds, n_fds, &(const struct timespec) {}, /* sigmask= */ NULL));
}
