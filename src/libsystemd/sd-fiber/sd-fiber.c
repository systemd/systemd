/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <threads.h>
#include <ucontext.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-fiber.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fiber.h"
#include "fiber-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log-context.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "time-util.h"

static thread_local ucontext_t main_context;

static int sd_fiber_allocate_stack(size_t size, void **ret) {
        void *stack = NULL;
        int r;

        assert(size % page_size() == 0);

        stack = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                     -1, 0);
        if (stack == MAP_FAILED)
                return -errno;

        /* Set up guard page at the bottom of the stack (grows downward) */
        r = RET_NERRNO(mprotect(stack, page_size(), PROT_NONE));
        if (r < 0) {
                (void) munmap(stack, size);
                return r;
        }

        *ret = TAKE_PTR(stack);
        return 0;
}

static void sd_fiber_entry_point(void) {
        sd_fiber *f;

        f = sd_fiber_current();
        assert(f);
        assert(f->func);
        assert(IN_SET(f->state, SD_FIBER_STATE_READY, SD_FIBER_STATE_CANCELLED));

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        f->result = f->state == SD_FIBER_STATE_CANCELLED ? -ECANCELED : f->func(f->userdata);
        f->state = SD_FIBER_STATE_COMPLETED;
}

static void reset_current_fiber(void) {
        sd_fiber_set_current(NULL);
        main_context = (ucontext_t) {};
}

static int sd_fiber_run(sd_fiber *f) {
        static bool installed = false;
        int r;

        if (f->state == SD_FIBER_STATE_COMPLETED)
                return -ESTALE;

        assert(IN_SET(f->state, SD_FIBER_STATE_READY, SD_FIBER_STATE_CANCELLED));

        if (!installed) {
                /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
                 * only half-documented (glibc doesn't document it but LSB does — though only superficially)
                 * we'll check for errors only in the most generic fashion possible. */

                r = pthread_atfork(NULL, NULL, reset_current_fiber);
                if (r != 0)
                        return -r;

                installed = true;
        }

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        log_debug("Scheduling fiber");

        sd_fiber_set_current(f);

        /* This looks innocent but this is where we start executing the fiber. Once it yields, we continue
         * here as if nothing happened. */
        if (swapcontext(&main_context, &f->context) < 0)
                return -errno;

        sd_fiber_set_current(NULL);

        switch (f->state) {

        case SD_FIBER_STATE_COMPLETED:
                if (f->result < 0)
                        log_debug_errno(f->result, "Fiber failed with error: %m");
                else
                        log_debug("Fiber finished executing");

                f->defer_event_source = sd_event_source_disable_unref(f->defer_event_source);
                f->exit_event_source = sd_event_source_disable_unref(f->exit_event_source);
                return f->result;

        case SD_FIBER_STATE_CANCELLED:
        case SD_FIBER_STATE_READY:
                log_debug("Fiber yielded execution");

                r = sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return r;
                break;

        case SD_FIBER_STATE_SUSPENDED:
                log_debug("Fiber suspended execution");
                /* Fiber is waiting for I/O - don't re-queue it */
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        return sd_fiber_run(f);
}

static int fiber_cancel_and_wait(sd_fiber *f) {
        int r;

        if (f->state == SD_FIBER_STATE_COMPLETED)
                return 0;

        r = sd_fiber_cancel(f);
        if (r < 0)
                return r;

        /* When sd_event_exit() is called, only exit sources will run, so we can't rely on the defer event
         * source for running the fiber until it completes here. */

        for (;;) {
                r = sd_fiber_run(f);
                if (f->state == SD_FIBER_STATE_COMPLETED)
                        break;
                if (r < 0)
                        return r;
        }

        return r == -ECANCELED ? 0 : r;
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        return fiber_cancel_and_wait(f);
}

static int fiber_makecontext(ucontext_t *ucp, const struct iovec *stack) {
        if (getcontext(ucp) < 0)
                return -errno;

        ucp->uc_stack.ss_sp = (uint8_t*) stack->iov_base + page_size();
        ucp->uc_stack.ss_size = stack->iov_len - page_size();
        ucp->uc_link = &main_context;
        makecontext(ucp, sd_fiber_entry_point, 0);

        return 0;
}

int sd_fiber_new_full(
                sd_event *e,
                const char *name,
                sd_fiber_func_t func,
                void *userdata,
                int64_t priority,
                sd_fiber **ret) {

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int r;

        assert(e);
        assert(name);
        assert(func);
        assert(ret);

        f = new(sd_fiber, 1);
        if (!f)
                return -ENOMEM;

        struct rlimit buffer = { .rlim_cur = 8388608 };
        if (getrlimit(RLIMIT_STACK, &buffer) < 0)
                log_debug_errno(errno, "Reading RLIMIT_STACK failed, ignoring: %m");

        *f = (sd_fiber) {
                .n_ref = 1,
                .stack_size = ROUND_UP(buffer.rlim_cur, page_size()),
                .state = SD_FIBER_STATE_READY,
                .name = strdup(name),
                .priority = priority,
                .func = func,
                .userdata = userdata,
        };
        if (!f->name)
                return -ENOMEM;

        if (e)
                f->event = sd_event_ref(e);
        else if (sd_fiber_current())
                f->event = sd_event_ref(sd_fiber_event(sd_fiber_current()));
        else {
                r = sd_event_default(&f->event);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_allocate_stack(f->stack_size, &f->stack);
        if (r < 0)
                return r;

        r = fiber_makecontext(&f->context, &IOVEC_MAKE(f->stack, f->stack_size));
        if (r < 0)
                return r;

        r = sd_event_add_defer(e, &f->defer_event_source, fiber_on_defer, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(f->defer_event_source, f->priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(f->defer_event_source, f->name);
        if (r < 0)
                return r;

        r = sd_event_add_exit(e, &f->exit_event_source, fiber_on_exit, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(f->exit_event_source, f->priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(f->exit_event_source, f->name);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_fiber_new(const char *name, sd_fiber_func_t func, void *userdata, sd_fiber **ret) {
        return sd_fiber_new_full(/* e= */ NULL, name, func, userdata, SD_FIBER_PRIORITY_DEFAULT, ret);
}

static sd_fiber *sd_fiber_free(sd_fiber *f) {
        if (!f)
                return NULL;

        (void) fiber_cancel_and_wait(f);

        (void) munmap(f->stack, f->stack_size);

        sd_event_source_disable_unref(f->defer_event_source);
        sd_event_source_disable_unref(f->exit_event_source);
        sd_event_unref(f->event);

        free(f->name);
        return mfree(f);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_fiber, sd_fiber, sd_fiber_free);

void sd_fiber_unref_many(sd_fiber **fibers, size_t size) {
        for (size_t i = 0; i < size; i++)
                sd_fiber_unref(fibers[i]);

        free(fibers);
}

const char* sd_fiber_name(const sd_fiber *f) {
        if (!f)
                f = sd_fiber_current();

        return ASSERT_PTR(f)->name;
}

sd_event* sd_fiber_event(const sd_fiber *f) {
        if (!f)
                f = sd_fiber_current();

        return ASSERT_PTR(f)->event;
}

int sd_fiber_set_exit_on_failure(sd_fiber *f, int b) {
        if (!f)
                f = sd_fiber_current();

        if (f->state == SD_FIBER_STATE_COMPLETED)
                return -ESTALE;

        return sd_event_source_set_exit_on_failure(ASSERT_PTR(f)->defer_event_source, b);
}

static int sd_fiber_swap(sd_fiber_state_t state) {
        sd_fiber *f = ASSERT_PTR(sd_fiber_current());

        f->state = state;
        f->result = 0;

        if (swapcontext(&f->context, &main_context) < 0)
                return -errno;

        /* When we get here, we've been resumed */

        return f->state == SD_FIBER_STATE_CANCELLED ? -ECANCELED : f->result;
}

int sd_fiber_yield(void) {
        return sd_fiber_swap(SD_FIBER_STATE_READY);
}

static inline int sd_fiber_suspend(void) {
        return sd_fiber_swap(SD_FIBER_STATE_SUSPENDED);
}

int sd_fiber_cancel(sd_fiber *f) {
        assert(f);
        assert(f != sd_fiber_current());

        if (IN_SET(f->state, SD_FIBER_STATE_COMPLETED, SD_FIBER_STATE_CANCELLED))
                return 0;

        f->state = SD_FIBER_STATE_CANCELLED;

        /* Once we cancel a fiber, we want to schedule the fiber until it completes. */
        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int sd_fiber_result(sd_fiber *f) {
        assert(f);
        assert(f->state == SD_FIBER_STATE_COMPLETED);

        return f->result;
}

static int fiber_io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        if (FLAGS_SET(revents, EPOLLERR)) {
                int error = 0;
                socklen_t len = sizeof(error);

                r = RET_NERRNO(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
                if (r < 0 && r != -ENOTSOCK)
                        return r;
                if (r >= 0)
                        f->result = -error;
        }

        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

typedef ssize_t (*FiberIOFunc)(int fd, void *args);

static ssize_t fiber_io_operation(int fd, uint32_t events, FiberIOFunc func, void *args) {
        sd_fiber *f;
        int r;

        assert(fd >= 0);
        assert(func);

        f = sd_fiber_current();

        /* If not in a fiber context, just call the function directly */
        if (!f)
                return func(fd, args);

        assert(f->event);

        /* Make fd non-blocking for fiber operations */
        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        /* Try the operation immediately */
        ssize_t n = func(fd, args);
        if (n >= 0)
                return n;

        if (r > 0) {
                r = fd_nonblock(fd, false);
                if (r < 0)
                        return r;
        }

        /* Operation would block - check if we're being cancelled */
        if (f->state == SD_FIBER_STATE_CANCELLED)
                return -ECANCELED;

        /* Duplicate fd to avoid EEXIST from epoll when adding the same fd multiple times */
        _cleanup_close_ int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0)
                return -errno;

        /* Set up I/O event source and suspend */
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(f->event, &s, fd_copy, events, fiber_io_callback, f);
        if (r < 0)
                return r;

        /* Make the event source own the duplicated fd so it's automatically closed */
        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return r;

        TAKE_FD(fd_copy);

        r = sd_event_source_set_priority(s, f->priority);
        if (r < 0)
                return r;

        /* Suspend fiber until I/O is ready */
        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        /* I/O is ready - retry the operation */
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

static int fiber_timeout_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        f->result = PTR_TO_INT(f->userdata);
        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int sd_fiber_ppoll(struct pollfd *fds, size_t n_fds, uint64_t timeout) {
        sd_fiber *f;
        int r;

        assert(fds || n_fds == 0);

        f = sd_fiber_current();

        if (!f)
                return ppoll_usec(fds, n_fds, timeout);

        assert(f->event);

        /* Try polling with zero timeout first to see if any are immediately ready */
        r = ppoll_usec(fds, n_fds, /* timeout= */ 0);
        if (timeout == 0 || r != 0) /* Either error or some fds are ready */
                return r;

        if (f->state == SD_FIBER_STATE_CANCELLED)
                return -ECANCELED;

        _cleanup_free_ sd_event_source **sources = NULL;
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *timer = NULL;

        sources = new0(sd_event_source*, n_fds);
        if (!sources)
                return -ENOMEM;

        CLEANUP_ARRAY(sources, n_fds, event_source_unref_many);

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

                /* Duplicate fd to avoid EEXIST from epoll when adding the same fd multiple times */
                _cleanup_close_ int fd_copy = fcntl(fds[i].fd, F_DUPFD_CLOEXEC, 3);
                if (fd_copy < 0)
                        return -errno;

                r = sd_event_add_io(f->event, &sources[i], fd_copy, events, fiber_io_callback, f);
                if (r < 0)
                        return r;

                r = sd_event_source_set_io_fd_own(sources[i], true);
                if (r < 0)
                        return r;

                TAKE_FD(fd_copy);

                r = sd_event_source_set_priority(sources[i], f->priority);
                if (r < 0)
                        return r;
        }

        if (timeout != USEC_INFINITY) {
                f->userdata = INT_TO_PTR(0);

                r = sd_event_add_time_relative(f->event, &timer, CLOCK_MONOTONIC,
                                               timeout, /* accuracy= */ 1, fiber_timeout_callback, f);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(timer, f->priority);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return ppoll_usec(fds, n_fds, /* timeout= */ 0);
}

int fd_wait_for_event_suspend(int fd, int event, usec_t timeout) {
        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };
        int r;

        r = sd_fiber_ppoll(&pollfd, 1, timeout);
        if (r <= 0)
                return r;

        return pollfd.revents;
}

int sd_fiber_sleep(uint64_t usec) {
        sd_fiber *f;
        int r;

        f = sd_fiber_current();

        if (!f)
                return usleep_safe(usec);

        if (usec == 0)
                return 0;

        assert(f->event);

        if (f->state == SD_FIBER_STATE_CANCELLED)
                return -ECANCELED;

        f->userdata = INT_TO_PTR(0);

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *timer = NULL;
        r = sd_event_add_time_relative(f->event, &timer, CLOCK_MONOTONIC,
                                       usec, /* accuracy= */ 1, fiber_timeout_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(timer, f->priority);
        if (r < 0)
                return r;

        return sd_fiber_suspend();
}

static int fiber_wait_check(sd_event_source *s, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        sd_fiber *target = ASSERT_PTR(f->userdata);
        int r;

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        if (target->state != SD_FIBER_STATE_COMPLETED)
                return 0;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int sd_fiber_wait_for(sd_fiber *target) {
        sd_fiber *f = ASSERT_PTR(sd_fiber_current());
        int r;

        assert(target);

        if (target->state == SD_FIBER_STATE_COMPLETED)
                return target->result;

        f->userdata = target;

        /* Target is not yet complete - set up post event source to wait for completion. */
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_post(f->event, &s, fiber_wait_check, f);
        if (r < 0)
                return r;

        /* Set priority lower than the target fiber's priority to ensure it runs after the target fiber's
         * defer event source. */
        r = sd_event_source_set_priority(s, f->priority);
        if (r < 0)
                return r;

        /* Suspend current fiber until target completes */
        return sd_fiber_suspend();
}

struct sd_fiber_waitgroup {
        sd_fiber **fibers;
        size_t n_fibers;
};

int sd_fiber_waitgroup_new(sd_fiber_waitgroup **ret) {
        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;

        assert(ret);

        wg = new(sd_fiber_waitgroup, 1);
        if (!wg)
                return -ENOMEM;

        *wg = (sd_fiber_waitgroup) {};

        *ret = TAKE_PTR(wg);
        return 0;
}

sd_fiber_waitgroup *sd_fiber_waitgroup_free(sd_fiber_waitgroup *wg) {
        if (!wg)
                return NULL;

        sd_fiber_unref_many(wg->fibers, wg->n_fibers);
        return mfree(wg);
}

int sd_fiber_waitgroup_add(sd_fiber_waitgroup *wg, sd_fiber *f) {
        assert(wg);
        assert(f);

        if (!GREEDY_REALLOC(wg->fibers, wg->n_fibers + 1))
                return -ENOMEM;

        wg->fibers[wg->n_fibers++] = sd_fiber_ref(f);
        return 0;
}

int sd_fiber_waitgroup_wait(sd_fiber_waitgroup *wg) {
        int r = 0;

        assert(wg);

        for (size_t i = 0; i < wg->n_fibers; i++)
                RET_GATHER(r, sd_fiber_wait_for(wg->fibers[i]));

        return MIN(r, 0);
}

int sd_fiber_waitgroup_check(sd_fiber_waitgroup *wg, sd_fiber **reterr) {
        assert(wg);

        for (size_t i = 0; i < wg->n_fibers; i++)
                if (sd_fiber_result(wg->fibers[i]) < 0) {
                        if (reterr)
                                *reterr = sd_fiber_ref(wg->fibers[i]);
                        return sd_fiber_result(wg->fibers[i]);
                }

        if (reterr)
                *reterr = NULL;

        return 0;
}

static int fiber_child_callback(sd_event_source *s, const siginfo_t *si, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int wait_for_terminate_suspend(pid_t pid, siginfo_t *ret) {
        sd_fiber *f;
        int r;

        assert(pid > 0);

        f = sd_fiber_current();

        if (!f)
                return wait_for_terminate(pid, ret);

        assert(f->event);

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_child(f->event, &s, pid, WEXITED|WNOWAIT, fiber_child_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, f->priority);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate(pid, ret);
}

int wait_for_terminate_and_check_suspend(const char *name, pid_t pid, WaitFlags flags) {
        int r;

        assert(pid > 0);

        sd_fiber *f = sd_fiber_current();

        if (!f)
                return wait_for_terminate_and_check(name, pid, flags);

        assert(f->event);

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_child(f->event, &s, pid, WEXITED|WNOWAIT, fiber_child_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, f->priority);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate_and_check(name, pid, flags);
}

int wait_for_terminate_with_timeout_suspend(pid_t pid, usec_t timeout) {
        sd_fiber *f;
        int r;

        assert(pid > 0);

        f = sd_fiber_current();

        if (!f)
                return wait_for_terminate_with_timeout(pid, timeout);

        assert(f->event);

        f->userdata = INT_TO_PTR(-ETIMEDOUT);

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *child_source = NULL;
        r = sd_event_add_child(f->event, &child_source, pid, WEXITED|WNOWAIT, fiber_child_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(child_source, f->priority);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *timer = NULL;
        r = sd_event_add_time_relative(f->event, &timer, CLOCK_MONOTONIC,
                                       timeout, /* accuracy= */ 1, fiber_timeout_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(timer, f->priority);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate(pid, /* ret= */ NULL);
}

void sigkill_wait_suspend(pid_t pid) {
        sd_fiber *f;

        assert(pid > 1);

        f = sd_fiber_current();

        if (!f) {
                sigkill_wait(pid);
                return;
        }

        (void) kill(pid, SIGKILL);
        (void) wait_for_terminate_suspend(pid, NULL);
}

void sigkill_wait_suspendp(pid_t *pid) {
        PROTECT_ERRNO;

        if (!pid)
                return;
        if (*pid <= 1)
                return;

        sigkill_wait_suspend(*pid);
}


static int fiber_event_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_fiber *f = ASSERT_PTR(userdata);
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int sd_event_run_suspend(sd_event *e, uint64_t timeout) {
        sd_fiber *f = ASSERT_PTR(sd_fiber_current());
        int r;

        assert(e);
        assert(f->event);

        r = sd_event_prepare(e);
        if (r < 0)
                return r;
        if (r == 0) {
                r = sd_event_wait(e, 0);
                if (r < 0)
                        return r;
        }
        if (r > 0)
                return sd_event_dispatch(e);

        if (timeout == 0)
                return 0;

        if (f->state == SD_FIBER_STATE_CANCELLED)
                return -ECANCELED;

        r = sd_event_prepare(e);
        if (r < 0)
                return r;

        int fd = sd_event_get_fd(e);
        if (fd < 0)
                return fd;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *io_source = NULL;
        r = sd_event_add_io(f->event, &io_source, fd, EPOLLIN, fiber_event_callback, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(io_source, f->priority);
        if (r < 0)
                return r;

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *timer_source = NULL;
        if (timeout != UINT64_MAX) {
                r = sd_event_add_time_relative(f->event, &timer_source, CLOCK_MONOTONIC,
                                               timeout, /* accuracy= */ 1, fiber_timeout_callback, f);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(timer_source, f->priority);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        r = sd_event_wait(e, 0);
        if (r <= 0)
                return r;

        return sd_event_dispatch(e);
}

static int fiber_bus_callback(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_fiber *f = ASSERT_PTR(userdata);

        if (f->state != SD_FIBER_STATE_SUSPENDED)
                return 0;

        *((sd_bus_message**) f->userdata) = sd_bus_message_ref(m);

        f->state = SD_FIBER_STATE_READY;

        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

int sd_bus_call_suspend(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply) {
        sd_fiber *f = ASSERT_PTR(sd_fiber_current());
        int r;

        assert(bus);
        assert(m);

        if (f->state == SD_FIBER_STATE_CANCELLED)
                return -ECANCELED;

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        f->userdata = &reply;

        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        r = sd_bus_call_async(bus, &slot, m, fiber_bus_callback, f, usec);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        if (sd_bus_message_is_method_error(reply, NULL)) {
                if (reterr_error)
                        sd_bus_error_copy(reterr_error, sd_bus_message_get_error(reply));
                return -sd_bus_message_get_errno(reply);
        }

        if (reterr_error)
                *reterr_error = SD_BUS_ERROR_NULL;
        if (ret_reply)
                *ret_reply = TAKE_PTR(reply);

        return 0;
}
