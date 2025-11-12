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
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fiber.h"
#include "fiber-util.h"
#include "future-internal.h"
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

#if HAS_FEATURE_ADDRESS_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

static thread_local ucontext_t main_context;

static int fiber_allocate_stack(size_t size, void **ret) {
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

static void fiber_entry_point(void) {
        Fiber *f = fiber_get_current();

        assert(f);
        assert(f->func);
        assert(IN_SET(f->state, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched from the main stack to a fiber. */
        __sanitizer_finish_switch_fiber(NULL, NULL, NULL);
#endif

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        f->result = f->state == FIBER_STATE_CANCELLED ? -ECANCELED : f->func(f->userdata);
        f->state = FIBER_STATE_COMPLETED;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the main stack from the completed fiber. When a fiber
         * finishes we have to pass NULL as the first argument to destroy the fake stack. */
        __sanitizer_start_switch_fiber(NULL, main_context.uc_stack.ss_sp, main_context.uc_stack.ss_size);
#endif
}

static void reset_current_fiber(void) {
        fiber_set_current(NULL);
        main_context = (ucontext_t) {};
}

static int fiber_run(Fiber *f) {
        static bool installed = false;
        int r;

        if (f->state == FIBER_STATE_COMPLETED)
                return -ESTALE;

        assert(IN_SET(f->state, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

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

        fiber_set_current(f);

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching to the fiber's stack.. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->context.uc_stack.ss_sp, f->context.uc_stack.ss_size);
#endif

        /* This looks innocent but this is where we start executing the fiber. Once it yields, we continue
         * here as if nothing happened. */
        if (swapcontext(&main_context, &f->context) < 0)
                return -errno;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the main stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        fiber_set_current(NULL);

        switch (f->state) {

        case FIBER_STATE_COMPLETED:
                if (f->result < 0)
                        log_debug_errno(f->result, "Fiber failed with error: %m");
                else
                        log_debug("Fiber finished executing");

                sd_future_resolve(f->future, f->result);

                f->defer_event_source = sd_event_source_disable_unref(f->defer_event_source);
                f->exit_event_source = sd_event_source_disable_unref(f->exit_event_source);
                return f->result;

        case FIBER_STATE_CANCELLED:
        case FIBER_STATE_READY:
                log_debug("Fiber yielded execution");

                r = sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return r;
                break;

        case FIBER_STATE_SUSPENDED:
                log_debug("Fiber suspended execution");
                /* Fiber is waiting for I/O - don't re-queue it */
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        return fiber_run(f);
}

int fiber_cancel(Fiber *f) {
        assert(f);
        assert(f != fiber_get_current());

        if (IN_SET(f->state, FIBER_STATE_COMPLETED, FIBER_STATE_CANCELLED))
                return 0;

        f->state = FIBER_STATE_CANCELLED;

        /* Once we cancel a fiber, we want to schedule the fiber until it completes. */
        return sd_event_source_set_enabled(f->defer_event_source, SD_EVENT_ONESHOT);
}

static int fiber_cancel_and_wait(Fiber *f) {
        int r;

        if (f->state == FIBER_STATE_COMPLETED)
                return 0;

        r = fiber_cancel(f);
        if (r < 0)
                return r;

        /* When sd_event_exit() is called, only exit sources will run, so we can't rely on the defer event
         * source for running the fiber until it completes here. */

        for (;;) {
                r = fiber_run(f);
                if (f->state == FIBER_STATE_COMPLETED)
                        break;
                if (r < 0)
                        return r;
        }

        return r == -ECANCELED ? 0 : r;
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        return fiber_cancel_and_wait(f);
}

static int fiber_makecontext(ucontext_t *ucp, const struct iovec *stack) {
        if (getcontext(ucp) < 0)
                return -errno;

        ucp->uc_stack.ss_sp = (uint8_t*) stack->iov_base + page_size();
        ucp->uc_stack.ss_size = stack->iov_len - page_size();
        ucp->uc_link = &main_context;
        makecontext(ucp, fiber_entry_point, 0);

        return 0;
}

int fiber_new(sd_event *e, const char *name, FiberFunc func, void *userdata, FiberDestroy destroy, sd_future *future, Fiber **ret) {
        _cleanup_(fiber_freep) Fiber *f = NULL;
        int r;

        assert(e);
        assert(func);
        assert(ret);

        f = new(Fiber, 1);
        if (!f)
                return -ENOMEM;

        struct rlimit buffer = { .rlim_cur = 8388608 };
        if (getrlimit(RLIMIT_STACK, &buffer) < 0)
                log_debug_errno(errno, "Reading RLIMIT_STACK failed, ignoring: %m");

        *f = (Fiber) {
                .stack_size = ROUND_UP(buffer.rlim_cur, page_size()),
                .state = FIBER_STATE_READY,
                .name = strdup(name),
                .func = func,
                .userdata = userdata,
                .destroy = destroy,
                .future = future,
        };
        if (!f->name)
                return -ENOMEM;

        if (e)
                f->event = sd_event_ref(e);
        else if (sd_fiber_is_running())
                f->event = sd_event_ref(sd_fiber_get_event());
        else {
                r = sd_event_default(&f->event);
                if (r < 0)
                        return r;
        }

        r = fiber_allocate_stack(f->stack_size, &f->stack);
        if (r < 0)
                return r;

        r = fiber_makecontext(&f->context, &IOVEC_MAKE(f->stack, f->stack_size));
        if (r < 0)
                return r;

        r = sd_event_add_defer(e, &f->defer_event_source, fiber_on_defer, f);
        if (r < 0)
                return r;

        r = sd_event_add_exit(e, &f->exit_event_source, fiber_on_exit, f);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

Fiber *fiber_free(Fiber *f) {
        if (!f)
                return NULL;

        (void) fiber_cancel_and_wait(f);

        if (f->destroy)
                f->destroy(f->userdata);

        (void) munmap(f->stack, f->stack_size);

        sd_event_source_disable_unref(f->defer_event_source);
        sd_event_source_disable_unref(f->exit_event_source);
        sd_event_unref(f->event);

        free(f->name);
        return mfree(f);
}

int sd_fiber_is_running(void) {
        return !!fiber_get_current();
}

const char* sd_fiber_get_name(void) {
        return ASSERT_PTR(fiber_get_current())->name;
}

sd_event* sd_fiber_get_event(void) {
        return ASSERT_PTR(fiber_get_current())->event;
}

int64_t sd_fiber_get_priority(void) {
        return ASSERT_PTR(fiber_get_current())->priority;
}

static int fiber_swap(FiberState state) {
        Fiber *f = ASSERT_PTR(fiber_get_current());

        f->state = state;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the main stack. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->context.uc_stack.ss_sp, f->context.uc_stack.ss_size);
#endif

        if (swapcontext(&f->context, &main_context) < 0)
                return -errno;

        /* When we get here, we've been resumed. */

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the fiber from the main stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        return f->state == FIBER_STATE_CANCELLED ? -ECANCELED : 0;
}

int sd_fiber_yield(void) {
        return fiber_swap(FIBER_STATE_READY);
}

static int fiber_suspend(void) {
        return fiber_swap(FIBER_STATE_SUSPENDED);
}

int fiber_result(Fiber *f) {
        assert(f);
        assert(f->state == FIBER_STATE_COMPLETED);

        return f->result;
}

int fiber_set_priority(Fiber *f, int64_t priority) {
        int r = 0;

        assert(f);

        if (f->defer_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->defer_event_source, priority));

        if (f->exit_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->exit_event_source, priority));

        return r;
}

static int fiber_resume(sd_future *f, void *userdata) {
        Fiber *fiber = ASSERT_PTR(userdata);

        if (fiber->state != FIBER_STATE_SUSPENDED)
                return 0;

        fiber->state = FIBER_STATE_READY;
        return sd_event_source_set_enabled(fiber->defer_event_source, SD_EVENT_ONESHOT);
}

typedef ssize_t (*FiberIOFunc)(int fd, void *args);

static ssize_t fiber_io_operation(int fd, uint32_t events, FiberIOFunc func, void *args) {
        Fiber *f = fiber_get_current();
        int r;

        assert(fd >= 0);
        assert(func);

        if (!f)
                return func(fd, args);

        assert(f->event);

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

        if (IN_SET(sd_event_get_state(f->event), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *io = NULL;
        r = sd_future_new_io(f->event, fd, events, &io);
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

        assert(f->event);

        /* Try polling with zero timeout first to see if any are immediately ready */
        r = ppoll_usec(fds, n_fds, /* timeout= */ 0);
        if (timeout == 0 || r != 0) /* Either error or some fds are ready */
                return r;

        if (IN_SET(sd_event_get_state(f->event), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

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

                r = sd_future_new_io(f->event, fds[i].fd, events, &futures[i]);
                if (r < 0)
                        return r;

                r = sd_future_set_callback(futures[i], fiber_resume, f);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        if (timeout != USEC_INFINITY) {
                r = sd_future_new_time_relative(f->event, CLOCK_MONOTONIC, timeout, /* accuracy= */ 1, &timer);
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
        Fiber *f = fiber_get_current();
        int r;

        if (!f)
                return usleep_safe(usec);

        if (usec == 0)
                return 0;

        assert(f->event);

        if (IN_SET(sd_event_get_state(f->event), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        r = sd_future_new_time_relative(f->event, CLOCK_MONOTONIC, usec, /* accuracy= */ 1, &timer);
        if (r < 0)
                return r;

        r = sd_future_set_callback(timer, fiber_resume, f);
        if (r < 0)
                return r;

        return fiber_suspend();
}

int sd_fiber_await(sd_future *target) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(target);

        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return 0;

        _cleanup_(sd_future_unrefp) sd_future *wait = NULL;
        r = sd_future_new_wait(target, &wait);
        if (r < 0)
                return r;

        r = sd_future_set_callback(wait, fiber_resume, f);
        if (r < 0)
                return r;

        return fiber_suspend();
}

struct sd_fiber_waitgroup {
        sd_future **futures;
        size_t n_futures;
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

        sd_future_unref_many(wg->futures, wg->n_futures);
        return mfree(wg);
}

int sd_fiber_waitgroup_add(sd_fiber_waitgroup *wg, sd_future *f) {
        assert(wg);
        assert(f);

        if (!GREEDY_REALLOC(wg->futures, wg->n_futures + 1))
                return -ENOMEM;

        wg->futures[wg->n_futures++] = sd_future_ref(f);
        return 0;
}

int sd_fiber_waitgroup_wait(sd_fiber_waitgroup *wg) {
        int r = 0;

        assert(wg);

        for (size_t i = 0; i < wg->n_futures; i++)
                RET_GATHER(r, sd_fiber_await(wg->futures[i]));

        return MIN(r, 0);
}

int sd_fiber_waitgroup_check(sd_fiber_waitgroup *wg, sd_future **reterr) {
        assert(wg);

        for (size_t i = 0; i < wg->n_futures; i++)
                if (sd_future_result(wg->futures[i]) < 0) {
                        if (reterr)
                                *reterr = sd_future_ref(wg->futures[i]);
                        return sd_future_result(wg->futures[i]);
                }

        if (reterr)
                *reterr = NULL;

        return 0;
}

int wait_for_terminate_suspend(pid_t pid, siginfo_t *ret) {
        Fiber *f = fiber_get_current();
        int r;

        assert(pid > 0);

        if (!f)
                return wait_for_terminate(pid, ret);

        assert(f->event);

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = sd_future_new_child(f->event, pid, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate(pid, ret);
}

int wait_for_terminate_and_check_suspend(const char *name, pid_t pid, WaitFlags flags) {
        Fiber *f = fiber_get_current();
        int r;

        assert(pid > 0);

        if (!f)
                return wait_for_terminate_and_check(name, pid, flags);

        assert(f->event);

        BLOCK_SIGNALS(SIGCHLD);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = sd_future_new_child(f->event, pid, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate_and_check(name, pid, flags);
}

void sigkill_wait_suspend(pid_t pid) {
        Fiber *f = fiber_get_current();

        assert(pid > 1);

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

int sd_event_run_suspend(sd_event *e, uint64_t timeout) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
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

        if (IN_SET(sd_event_get_state(f->event), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_event_prepare(e);
        if (r < 0)
                return r;

        int fd = sd_event_get_fd(e);
        if (fd < 0)
                return fd;

        _cleanup_(sd_future_unrefp) sd_future *io = NULL;
        r = sd_future_new_io(f->event, fd, EPOLLIN, &io);
        if (r < 0)
                return r;

        r = sd_future_set_callback(io, fiber_resume, f);
        if (r < 0)
                return r;

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        if (timeout != USEC_INFINITY) {
                r = sd_future_new_time_relative(f->event, CLOCK_MONOTONIC, timeout, /* accuracy= */ 1, &timer);
                if (r < 0)
                        return r;

                r = sd_future_set_callback(timer, fiber_resume, f);
                if (r < 0)
                        return r;
        }

        r = fiber_suspend();
        if (r < 0)
                return r;

        r = sd_event_wait(e, 0);
        if (r <= 0)
                return r;

        return sd_event_dispatch(e);
}

int sd_bus_call_suspend(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(bus);
        assert(m);

        if (IN_SET(sd_event_get_state(f->event), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *call = NULL;
        r = sd_bus_call_future(bus, m, usec, &call);
        if (r < 0)
                return r;

        r = sd_future_set_callback(call, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        sd_bus_message *reply;
        r = sd_future_bus_reply(call, &reply);
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
                *ret_reply = sd_bus_message_ref(reply);

        return 0;
}
