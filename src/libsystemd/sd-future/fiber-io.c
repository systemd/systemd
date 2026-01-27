/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>          /* IWYU pragma: keep */
#include <time.h>
#include <unistd.h>

#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fiber.h"
#include "io-util.h"
#include "socket-util.h"

typedef ssize_t (*FiberIOFunc)(int fd, void *args);

static ssize_t fiber_io_operation(int fd, uint32_t events, FiberIOFunc func, void *args) {
        Fiber *f = fiber_get_current();
        int r;

        assert(fd >= 0);
        assert(func);

        if (!f)
                return func(fd, args);

        assert(sd_fiber_get_event());

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        ssize_t n = func(fd, args);
        if (n >= 0)
                return n;

        if (r > 0) {
                r = fd_nonblock(fd, false);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_future_unrefp) sd_future *io = NULL;
        r = sd_future_new_io(sd_fiber_get_event(), fd, events, &io);
        if (r < 0)
                return r;

        r = sd_future_set_callback(io, fiber_resume, fiber_get_current());
        if (r < 0)
                return r;

        r = fiber_suspend();
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
        assert(fd >= 0);
        assert(buf || count == 0);

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
        assert(fd >= 0);
        assert(buf || count == 0);

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
        assert(fd >= 0);
        assert(iov || iovcnt == 0);

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
        assert(fd >= 0);
        assert(iov || iovcnt == 0);

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
        assert(sockfd >= 0);
        assert(buf || len == 0);

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
        assert(sockfd >= 0);
        assert(buf || len == 0);

        return fiber_io_operation(sockfd, EPOLLOUT, send_callback, &(SendArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
        });
}

typedef struct ConnectArgs {
        const struct sockaddr *addr;
        socklen_t addrlen;
} ConnectArgs;

static ssize_t connect_callback(int fd, void *args) {
        ConnectArgs *a = ASSERT_PTR(args);

        return RET_NERRNO(connect(fd, a->addr, a->addrlen));
}

int sd_fiber_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        assert(sockfd >= 0);
        assert(addr);

        return fiber_io_operation(sockfd, EPOLLOUT, connect_callback, &(ConnectArgs) {
                .addr = addr,
                .addrlen = addrlen,
        });
}

typedef struct RecvmsgArgs {
        struct msghdr *msg;
        int flags;
} RecvmsgArgs;

static ssize_t recvmsg_callback(int fd, void *args) {
        RecvmsgArgs *a = ASSERT_PTR(args);

        return recvmsg_safe(fd, a->msg, a->flags);
}

ssize_t sd_fiber_recvmsg(int sockfd, struct msghdr *msg, int flags) {
        assert(sockfd >= 0);
        assert(msg);

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
        assert(sockfd >= 0);
        assert(msg);

        return fiber_io_operation(sockfd, EPOLLOUT, sendmsg_callback, &(SendmsgArgs) {
                .msg = msg,
                .flags = flags,
        });
}

typedef struct RecvfromArgs {
        void *buf;
        size_t len;
        int flags;
        struct sockaddr *src_addr;
        socklen_t *addrlen;
} RecvfromArgs;

static ssize_t recvfrom_callback(int fd, void *args) {
        RecvfromArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = recvfrom(fd, a->buf, a->len, a->flags, a->src_addr, a->addrlen);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
        assert(sockfd >= 0);
        assert(buf || len == 0);

        return fiber_io_operation(sockfd, EPOLLIN, recvfrom_callback, &(RecvfromArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
                .src_addr = src_addr,
                .addrlen = addrlen,
        });
}

typedef struct SendtoArgs {
        const void *buf;
        size_t len;
        int flags;
        const struct sockaddr *dest_addr;
        socklen_t addrlen;
} SendtoArgs;

static ssize_t sendto_callback(int fd, void *args) {
        SendtoArgs *a = ASSERT_PTR(args);
        ssize_t n;

        n = sendto(fd, a->buf, a->len, a->flags, a->dest_addr, a->addrlen);
        return n >= 0 ? n : -errno;
}

ssize_t sd_fiber_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
        assert(sockfd >= 0);
        assert(buf || len == 0);

        return fiber_io_operation(sockfd, EPOLLOUT, sendto_callback, &(SendtoArgs) {
                .buf = buf,
                .len = len,
                .flags = flags,
                .dest_addr = dest_addr,
                .addrlen = addrlen,
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
        assert(sockfd >= 0);

        return fiber_io_operation(sockfd, EPOLLIN, accept_callback, &(AcceptArgs) {
                .addr = addr,
                .addrlen = addrlen,
                .flags = flags,
        });
}

int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, uint64_t timeout) {
        Fiber *f = fiber_get_current();
        int r;

        assert(fds || n_fds == 0);

        if (!f)
                return ppoll_usec(fds, n_fds, timeout);

        assert(sd_fiber_get_event());

        /* Try polling with zero timeout first to see if any are immediately ready */
        r = ppoll_usec(fds, n_fds, /* timeout= */ 0);
        if (timeout == 0 || r != 0) /* Either error or some fds are ready */
                return r;

        _cleanup_free_ sd_future **futures = NULL;
        CLEANUP_ARRAY(futures, n_fds, sd_future_unref_many);

        futures = new0(sd_future*, n_fds);
        if (!futures)
                return -ENOMEM;

        /* Set up I/O event sources for all valid fds */
        for (size_t i = 0; i < n_fds; i++) {
                if (fds[i].fd < 0)
                        continue;

                uint32_t events = 0;
                if (fds[i].events & POLLIN)
                        events |= EPOLLIN;
                if (fds[i].events & POLLOUT)
                        events |= EPOLLOUT;
                if (fds[i].events & POLLPRI)
                        events |= EPOLLPRI;

                if (events == 0)
                        continue;

                r = sd_future_new_io(sd_fiber_get_event(), fds[i].fd, events, &futures[i]);
                if (r < 0)
                        return r;

                r = sd_future_set_callback(futures[i], fiber_resume, f);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        if (timeout != USEC_INFINITY) {
                r = sd_future_new_time_relative(sd_fiber_get_event(), CLOCK_MONOTONIC, timeout, /* accuracy= */ 1, &timer);
                if (r < 0)
                        return r;

                r = sd_future_set_callback(timer, fiber_resume, f);
                if (r < 0)
                        return r;
        }

        r = fiber_suspend();
        if (r < 0)
                return r;

        return ppoll_usec(fds, n_fds, /* timeout= */ 0);
}
