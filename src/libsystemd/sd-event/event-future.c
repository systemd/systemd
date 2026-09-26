/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "constants.h"
#include "errno-util.h"
#include "event-future.h"
#include "event-util.h"
#include "fd-util.h"
#include "pidref.h"
#include "time-util.h"

int event_source_inherit_fiber_priority(sd_event_source *s) {
        int64_t priority;
        int r;

        assert(s);

        if (!sd_fiber_is_running())
                return 0;

        r = sd_fiber_get_priority(&priority);
        if (r < 0)
                return r;

        return sd_event_source_set_priority(s, priority);
}

typedef struct IoFuture {
        sd_event_source *source;
} IoFuture;

static void* io_future_alloc(void) {
        return new0(IoFuture, 1);
}

static void io_future_free(sd_future *f) {
        IoFuture *iof = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        sd_event_source_unref(iof->source);
        free(iof);
}

static int io_future_cancel(sd_future *f) {
        IoFuture *iof = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r = 0;

        RET_GATHER(r, sd_event_source_set_enabled(iof->source, SD_EVENT_OFF));
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int io_future_set_priority(sd_future *f, int64_t priority) {
        IoFuture *iof = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        return sd_event_source_set_priority(iof->source, priority);
}

static const sd_future_ops io_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = io_future_alloc,
        .free = io_future_free,
        .cancel = io_future_cancel,
        .set_priority = io_future_set_priority,
};

static int io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        /* Resolve with the revents mask on success (matching io_uring poll_add's CQE convention) so
         * callers can read it directly off the future result. EPOLLERR is the one exception: surface
         * the actual socket error via SO_ERROR so callers like sd_fiber_connect() can return -errno
         * directly without re-querying. */
        if (FLAGS_SET(revents, EPOLLERR)) {
                int error = 0;
                socklen_t len = sizeof(error);

                int r = RET_NERRNO(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
                if (r == -ENOTSOCK)
                        return sd_future_resolve(f, (int) revents);
                if (r >= 0 && error != 0)
                        return sd_future_resolve(f, -error);
                if (r >= 0)
                        /* EPOLLERR was reported but SO_ERROR returned no pending error (e.g.
                         * already consumed elsewhere). Surface the revents mask so the caller
                         * still sees the error condition rather than mistaking it for success. */
                        return sd_future_resolve(f, (int) revents);
                /* On any other getsockopt() error fall through and resolve the future with that
                 * error so the waiting fiber wakes up rather than hanging forever. */
                return sd_future_resolve(f, r);
        }

        return sd_future_resolve(f, (int) revents);
}

int future_new_io(sd_event *e, int fd, uint32_t events, sd_future **ret) {
        int r;

        assert(e);
        assert(fd >= 0);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(e, &io_future_ops, &f);
        if (r < 0)
                return r;

        IoFuture *iof = sd_future_get_private(f);

        /* Duplicate fd to avoid EEXIST from epoll when adding the same fd multiple times */
        _cleanup_close_ int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0)
                return -errno;

        r = sd_event_add_io(e, &iof->source, fd_copy, events, io_handler, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(iof->source, true);
        if (r < 0)
                return r;

        TAKE_FD(fd_copy);

        r = sd_event_source_set_enabled(iof->source, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        r = event_source_inherit_fiber_priority(iof->source);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int future_group_add_io(sd_future *group, int fd, uint32_t events) {
        _cleanup_(sd_future_cancel_unrefp) sd_future *io = NULL;
        int r;

        assert(group);

        r = future_new_io(sd_future_get_event(group), fd, events, &io);
        if (r < 0)
                return r;

        r = sd_future_group_add(group, io);
        if (r < 0)
                return r;

        /* The group owns a reference now: release ours without cancelling the child. */
        io = sd_future_unref(io);
        return 0;
}

typedef struct ChildFuture {
        sd_event_source *source;
        int options;                    /* waitid() options the source was created with. */
        siginfo_t siginfo;
        bool exited;
        bool process_own;
        int signal;                     /* Last signal sent by cancellation, 0 if none. */
        usec_t kill_timeout;
        sd_event_source *kill_timer;
} ChildFuture;

static void* child_future_alloc(void) {
        return new0(ChildFuture, 1);
}

static void child_future_free(sd_future *f) {
        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        sd_event_source_unref(cf->source);
        sd_event_source_unref(cf->kill_timer);
        free(cf);
}

static int child_future_escalate(sd_future *f);

static int child_kill_timer_handler(sd_event_source *s, usec_t usec, void *userdata) {
        return child_future_escalate(ASSERT_PTR(userdata));
}

/* Each attempt escalates, and the handler resolves the future once the process is gone. */
static int child_future_escalate(sd_future *f) {
        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        if (cf->signal == SIGKILL)
                return 0;

        int signo = cf->signal == SIGTERM ? SIGKILL : SIGTERM;

        /* Send first: if this fails the next attempt should retry the same signal. */
        r = sd_event_source_send_child_signal(cf->source, signo, /* si= */ NULL, /* flags= */ 0);
        if (r < 0 && r != -ESRCH) {
                /* We'll never manage to terminate it (-EPERM, say), so resolve rather than leave
                 * awaiters hanging. */
                cf->kill_timer = sd_event_source_disable_unref(cf->kill_timer);
                RET_GATHER(r, sd_future_resolve(f, r));
                return r;
        }

        cf->signal = signo;

        /* Nothing left to escalate to, or already gone and the handler will pick it up. */
        if (signo == SIGKILL || r == -ESRCH) {
                cf->kill_timer = sd_event_source_disable_unref(cf->kill_timer);
                return 0;
        }

        if (cf->kill_timeout == USEC_INFINITY)
                return 0;

        r = sd_event_add_time_relative(
                        sd_future_get_event(f),
                        &cf->kill_timer,
                        CLOCK_MONOTONIC,
                        cf->kill_timeout,
                        /* accuracy= */ 0,
                        child_kill_timer_handler,
                        f);
        if (r < 0)
                return r;

        int64_t priority;
        r = sd_event_source_get_priority(cf->source, &priority);
        if (r < 0)
                return r;

        return sd_event_source_set_priority(cf->kill_timer, priority);
}

static int child_future_cancel(sd_future *f) {
        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        if (cf->process_own)
                return child_future_escalate(f);

        /* Drop the source rather than disabling it: sd-event keeps its per-PID slot claimed until
         * the source is disconnected, failing a later sd_event_add_child*() with -EBUSY. */
        cf->source = sd_event_source_disable_unref(cf->source);

        return sd_future_resolve(f, -ECANCELED);
}

static int child_future_set_priority(sd_future *f, int64_t priority) {
        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        r = sd_event_source_set_priority(cf->source, priority);
        if (r < 0)
                return r;

        if (cf->kill_timer)
                return sd_event_source_set_priority(cf->kill_timer, priority);

        return 0;
}

static const sd_future_ops child_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = child_future_alloc,
        .free = child_future_free,
        .cancel = child_future_cancel,
        .set_priority = child_future_set_priority,
};

static int child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(f));

        cf->siginfo = *ASSERT_PTR(si);
        cf->exited = true;
        cf->kill_timer = sd_event_source_disable_unref(cf->kill_timer);

        return sd_future_resolve(f, cf->signal > 0 ? -ECANCELED : 0);
}

int future_new_child(sd_event *e, const PidRef *pidref, int options, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;
        if (pidref->fd < 0)
                return -ENOMEDIUM;

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(e, &child_future_ops, &f);
        if (r < 0)
                return r;

        ChildFuture *cf = sd_future_get_private(f);
        cf->kill_timeout = DEFAULT_TIMEOUT_USEC;
        cf->options = options;

        /* The source gets its own duplicate of the pidfd so the caller's PidRef stays untouched. */
        r = event_add_child_pidref(e, &cf->source, pidref, options, child_handler, f);
        if (r < 0)
                return r;

        r = event_source_inherit_fiber_priority(cf->source);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int future_child_get_siginfo(sd_future *f, siginfo_t *ret) {
        assert_return(f, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(sd_future_get_ops(f) == &child_future_ops, -EINVAL);

        if (sd_future_state(f) != SD_FUTURE_RESOLVED)
                return -EAGAIN;

        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(f));
        if (!cf->exited)
                return sd_future_result(f);

        *ret = cf->siginfo;
        return 0;
}

int future_child_set_process_own(sd_future *f, int own) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &child_future_ops, -EINVAL);

        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(f));
        /* Ownership has to see the process exit and reap it: WSTOPPED/WCONTINUED would resolve
         * while it is still alive, WNOWAIT would leave a zombie. */
        assert_return(!own || cf->options == WEXITED, -EINVAL);

        cf->process_own = own;
        return 0;
}

int future_child_set_kill_timeout(sd_future *f, uint64_t usec) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &child_future_ops, -EINVAL);

        ChildFuture *cf = ASSERT_PTR(sd_future_get_private(f));
        cf->kill_timeout = usec;
        return 0;
}

int future_group_add_child(sd_future *group, const PidRef *pidref, int options) {
        _cleanup_(sd_future_cancel_unrefp) sd_future *child = NULL;
        int r;

        assert(group);

        r = future_new_child(sd_future_get_event(group), pidref, options, &child);
        if (r < 0)
                return r;

        r = sd_future_group_add(group, child);
        if (r < 0)
                return r;

        /* The group owns a reference now: release ours without cancelling the child. */
        child = sd_future_unref(child);
        return 0;
}

typedef struct DeferFuture {
        sd_event_source *source;
        int result;
} DeferFuture;

static void* defer_future_alloc(void) {
        return new0(DeferFuture, 1);
}

static void defer_future_free(sd_future *f) {
        DeferFuture *df = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        sd_event_source_unref(df->source);
        free(df);
}

static int defer_future_cancel(sd_future *f) {
        DeferFuture *df = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        r = sd_event_source_set_enabled(df->source, SD_EVENT_OFF);
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int defer_future_set_priority(sd_future *f, int64_t priority) {
        DeferFuture *df = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        return sd_event_source_set_priority(df->source, priority);
}

static const sd_future_ops defer_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = defer_future_alloc,
        .free = defer_future_free,
        .cancel = defer_future_cancel,
        .set_priority = defer_future_set_priority,
};

static int defer_handler(sd_event_source *s, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        DeferFuture *df = ASSERT_PTR(sd_future_get_private(f));
        return sd_future_resolve(f, df->result);
}

int sd_future_new_defer(sd_event *e, int result, sd_future **ret) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(ret, -EINVAL);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(e, &defer_future_ops, &f);
        if (r < 0)
                return r;

        DeferFuture *df = sd_future_get_private(f);
        df->result = result;

        r = sd_event_add_defer(e, &df->source, defer_handler, f);
        if (r < 0)
                return r;

        r = event_source_inherit_fiber_priority(df->source);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

typedef struct TimeFuture {
        sd_event_source *source;

        /* Result the future resolves with on natural expiry (vs. cancellation). 0 for normal sleep,
         * non-zero (e.g. -ETIMEDOUT) lets a fiber waiting on this future resume with that error. */
        int result;
} TimeFuture;

static void* time_future_alloc(void) {
        return new0(TimeFuture, 1);
}

static void time_future_free(sd_future *f) {
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        sd_event_source_unref(tf->source);
        free(tf);
}

static int time_future_cancel(sd_future *f) {
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        r = sd_event_source_set_enabled(tf->source, SD_EVENT_OFF);
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int time_future_set_priority(sd_future *f, int64_t priority) {
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        return sd_event_source_set_priority(tf->source, priority);
}

static const sd_future_ops time_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = time_future_alloc,
        .free = time_future_free,
        .cancel = time_future_cancel,
        .set_priority = time_future_set_priority,
};

static int time_handler(sd_event_source *s, usec_t usec, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(f));

        return sd_future_resolve(f, tf->result);
}

typedef int (*event_add_time_func)(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata);

static int future_new_time_internal(
                event_add_time_func add_time,
                sd_event *e,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                int result,
                sd_future **ret) {

        int r;

        assert(add_time);
        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(e, &time_future_ops, &f);
        if (r < 0)
                return r;

        TimeFuture *tf = sd_future_get_private(f);
        tf->result = result;

        r = add_time(e, &tf->source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        r = event_source_inherit_fiber_priority(tf->source);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        return future_new_time_internal(sd_event_add_time, e, clock, usec, accuracy, result, ret);
}

int future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        return future_new_time_internal(sd_event_add_time_relative, e, clock, usec, accuracy, result, ret);
}

int future_group_add_time_relative(sd_future *group, clockid_t clock, uint64_t usec, uint64_t accuracy, int result) {
        _cleanup_(sd_future_cancel_unrefp) sd_future *timer = NULL;
        int r;

        assert(group);

        r = future_new_time_relative(sd_future_get_event(group), clock, usec, accuracy, result, &timer);
        if (r < 0)
                return r;

        r = sd_future_group_add(group, timer);
        if (r < 0)
                return r;

        /* The group owns a reference now: release ours without cancelling the child. */
        timer = sd_future_unref(timer);
        return 0;
}

int event_run_suspend(sd_event *e, uint64_t timeout) {
        sd_event *outer = sd_fiber_get_event();
        int r;

        assert(e);
        assert(sd_fiber_is_running());
        assert(outer);
        assert(e != outer);

        /* Make sure that none of the preparation callbacks ends up freeing the event source under our feet */
        PROTECT_EVENT(e);

        r = sd_event_prepare(e);
        if (r < 0)
                return r;
        if (r == 0) {
                r = sd_event_wait(e, 0);
                if (r < 0)
                        return r;
        }
        if (r > 0) {
                r = sd_event_dispatch(e);
                if (r < 0)
                        return r;

                return 1;
        }

        if (timeout == 0)
                return 0;

        int fd = sd_event_get_fd(e);
        if (fd < 0)
                return fd;

        /* Wait for the inner-loop fd to become readable OR (optionally) the timeout to fire. */
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *group = NULL;
        r = sd_future_group_new(outer, &group);
        if (r < 0)
                return r;

        r = sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY);
        if (r < 0)
                return r;

        r = future_group_add_io(group, fd, EPOLLIN);
        if (r < 0)
                return r;

        if (timeout != USEC_INFINITY) {
                r = future_group_add_time_relative(
                                group,
                                CLOCK_MONOTONIC,
                                timeout,
                                /* accuracy= */ 1,
                                /* result= */ 0);
                if (r < 0)
                        return r;
        }

        r = sd_fiber_await(group);
        if (r < 0)
                return r;

        r = sd_future_result(group);
        if (r < 0)
                return r;

        r = sd_event_prepare(e);
        if (r == 0)
                r = sd_event_wait(e, 0);
        if (r > 0) {
                r = sd_event_dispatch(e);
                if (r < 0)
                        return r;

                return 1;
        }

        return r;
}
