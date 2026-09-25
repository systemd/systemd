/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "event-future.h"
#include "fd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "tests.h"
#include "time-util.h"

typedef enum EventFutureType {
        EVENT_FUTURE_IO,
        EVENT_FUTURE_DEFER,
        EVENT_FUTURE_TIME,
        EVENT_FUTURE_TIME_RELATIVE,
        _EVENT_FUTURE_TYPE_MAX,
        _EVENT_FUTURE_TYPE_INVALID = -EINVAL,
} EventFutureType;

static int new_event_future(EventFutureType type, sd_event *e, int fd, sd_future **ret) {
        switch (type) {
        case EVENT_FUTURE_IO:
                return future_new_io(e, fd, EPOLLIN, ret);
        case EVENT_FUTURE_DEFER:
                return sd_future_new_defer(e, 0, ret);
        case EVENT_FUTURE_TIME:
                return future_new_time(e, CLOCK_MONOTONIC, 0, 1, 0, ret);
        case EVENT_FUTURE_TIME_RELATIVE:
                return future_new_time_relative(e, CLOCK_MONOTONIC, 0, 1, 0, ret);
        default:
                assert_not_reached();
        }
}

/* Forks a child that exits with the given status, or that blocks forever if status is negative. */
static int fork_child(int status, PidRef *ret) {
        int r;

        r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, ret);
        if (r < 0)
                return r;
        if (r == 0) {
                while (status < 0)
                        pause();

                _exit(status);
        }

        return 0;
}

/* Forks a child that ignores SIGTERM and blocks forever. Returns once the child has set that up. */
static int fork_stubborn_child(PidRef *ret) {
        _cleanup_close_pair_ int ready[2] = EBADF_PAIR;
        char c;
        int r;

        if (pipe2(ready, O_CLOEXEC) < 0)
                return -errno;

        r = pidref_safe_fork("(stubborn-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG, ret);
        if (r < 0)
                return r;
        if (r == 0) {
                (void) ignore_signals(SIGTERM);
                (void) write(ready[1], "x", 1);
                for (;;)
                        pause();
        }

        ready[1] = safe_close(ready[1]);
        if (read(ready[0], &c, 1) != 1)
                return -EIO;

        return 0;
}

TEST(future_child) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_child(42, &pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_ERROR(future_child_get_siginfo(f, &si), EAGAIN);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(f));
        ASSERT_OK(future_child_get_siginfo(f, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, 42);
        ASSERT_EQ(si.si_pid, pidref.pid);

        /* The child was reaped along with the resolution. */
        ASSERT_ERROR(pidref_kill(&pidref, 0), ESRCH);
}

TEST(future_child_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(fork_child(-1, &pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK_ZERO(sd_event_run(e, 0));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_ERROR(future_child_get_siginfo(f, &si), ECANCELED);

        /* Cancellation leaves the process alone: still running, and the caller's pidfd still usable. */
        ASSERT_OK(pidref_kill(&pidref, 0));

        /* It also releases sd-event's per-process child slot right away. */
        _cleanup_(sd_future_cancel_unrefp) sd_future *g = NULL;
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &g));

        ASSERT_OK(pidref_kill(&pidref, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
}

TEST(future_child_process_own) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_child(-1, &pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_OK(future_child_set_process_own(f, true));

        /* Cancellation asks the process to terminate and keeps waiting for it. */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_OK(future_child_get_siginfo(f, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGTERM);
        ASSERT_ERROR(pidref_kill(&pidref, 0), ESRCH);
}

TEST(future_child_process_own_escalates) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_stubborn_child(&pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_OK(future_child_set_process_own(f, true));

        /* SIGTERM is ignored, so the first attempt changes nothing. */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK_ZERO(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);
        ASSERT_OK(pidref_kill(&pidref, 0));

        /* The second attempt escalates to SIGKILL. */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_OK(future_child_get_siginfo(f, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
        ASSERT_ERROR(pidref_kill(&pidref, 0), ESRCH);
}

TEST(future_child_process_own_kill_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_stubborn_child(&pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_OK(future_child_set_process_own(f, true));
        ASSERT_OK(future_child_set_kill_timeout(f, 10 * USEC_PER_MSEC));

        /* A single cancellation suffices: the timer escalates to SIGKILL on its own. */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_OK(future_child_get_siginfo(f, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
        ASSERT_ERROR(pidref_kill(&pidref, 0), ESRCH);
}

static int child_cancel_wait_fiber(void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        /* The timeout interrupts the wait after SIGTERM, which makes the cleanup loop cancel again
         * and thereby escalate to SIGKILL. */
        SD_FIBER_TIMEOUT(10 * USEC_PER_MSEC);
        sd_future_cancel_wait_unref(sd_future_ref(f));
        return 0;
}

TEST(future_child_process_own_cancel_wait) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL, *fiber = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_stubborn_child(&pidref));
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        ASSERT_OK(future_child_set_process_own(f, true));
        ASSERT_OK(sd_fiber_new(e, "child-cancel-wait", child_cancel_wait_fiber, f, /* destroy= */ NULL, &fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_OK(future_child_get_siginfo(f, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
        ASSERT_ERROR(pidref_kill(&pidref, 0), ESRCH);
}

TEST(future_child_invalid) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL, *g = NULL, *defer = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_ERROR(future_new_child(e, &PIDREF_NULL, WEXITED, &f), ESRCH);
        ASSERT_OK(fork_child(-1, &pidref));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_new_child(e, &pidref, 0, &f)), EINVAL);
        ASSERT_OK(future_new_child(e, &pidref, WEXITED, &f));
        /* sd-event allows one child source per process. */
        ASSERT_ERROR(future_new_child(e, &pidref, WEXITED, &g), EBUSY);

        ASSERT_OK(sd_future_new_defer(e, 0, &defer));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_child_get_siginfo(defer, &si)), EINVAL);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_child_set_process_own(defer, true)), EINVAL);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_child_set_kill_timeout(defer, 0)), EINVAL);
}

/* Ownership is rejected for waitid() options it cannot honour. */
TEST(future_child_process_own_rejects_options) {
        int options;

        /* WSTOPPED and WCONTINUED need SIGCHLD blocked before sd-event will watch for them. */
        BLOCK_SIGNALS(SIGCHLD);

        FOREACH_ARGUMENT(options, WEXITED|WNOWAIT, WEXITED|WSTOPPED, WSTOPPED|WCONTINUED) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
                _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(fork_child(-1, &pidref));
                ASSERT_OK(future_new_child(e, &pidref, options, &f));
                ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_child_set_process_own(f, true)), EINVAL);
                /* Turning ownership off is always fine. */
                ASSERT_OK(future_child_set_process_own(f, false));
        }
}

static int child_await_fiber(void *userdata) {
        PidRef *pidref = ASSERT_PTR(userdata);
        siginfo_t si;
        int r;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        r = future_new_child(sd_fiber_get_event(), pidref, WEXITED, &f);
        if (r < 0)
                return r;

        r = sd_fiber_await(f);
        if (r < 0)
                return r;

        r = future_child_get_siginfo(f, &si);
        if (r < 0)
                return r;

        return si.si_code == CLD_EXITED ? si.si_status : -EIO;
}

TEST(future_child_await) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(fork_child(7, &pidref));
        ASSERT_OK(sd_fiber_new(e, "child-await", child_await_fiber, &pidref, /* destroy= */ NULL, &fiber));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(fiber), 7);
}

TEST(future_group_add_child) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *group = NULL;
        _cleanup_(pidref_done) PidRef a = PIDREF_NULL, b = PIDREF_NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(fork_child(1, &a));
        ASSERT_OK(fork_child(2, &b));
        ASSERT_OK(future_group_add_child(group, &a, WEXITED));
        ASSERT_OK(future_group_add_child(group, &b, WEXITED));
        ASSERT_EQ(sd_future_group_size(group), 2U);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(group));
        ASSERT_ERROR(pidref_kill(&a, 0), ESRCH);
        ASSERT_ERROR(pidref_kill(&b, 0), ESRCH);
}

typedef struct EventFuturePriorityData {
        EventFutureType type;
        int fd;
        sd_future **ret;
} EventFuturePriorityData;

static int event_future_priority_fiber(void *userdata) {
        EventFuturePriorityData *d = ASSERT_PTR(userdata);

        return new_event_future(d->type, sd_fiber_get_event(), d->fd, d->ret);
}

TEST(event_future_priority) {
        int64_t priority, probe_priority;

        for (EventFutureType type = 0; type < _EVENT_FUTURE_TYPE_MAX; type++)
                FOREACH_ARGUMENT(priority, -10, 0, 10)
                        FOREACH_ARGUMENT(probe_priority, -5, 5) {
                                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                                _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
                                _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL, *probe = NULL;

                                ASSERT_OK(sd_event_new(&e));
                                if (type == EVENT_FUTURE_IO) {
                                        ASSERT_OK_ERRNO(pipe2(fds, O_CLOEXEC | O_NONBLOCK));
                                        ASSERT_OK_EQ_ERRNO(write(fds[1], "X", 1), 1);
                                }

                                if (priority != 0) {
                                        _cleanup_(sd_future_unrefp) sd_future *registrar = NULL;
                                        EventFuturePriorityData d = { .type = type, .fd = fds[0], .ret = &f };

                                        ASSERT_OK(sd_fiber_new(e, "new-event-future", event_future_priority_fiber,
                                                              &d, /* destroy= */ NULL, &registrar));
                                        ASSERT_OK(sd_future_set_priority(registrar, priority));
                                        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                                        ASSERT_OK_ZERO(sd_future_result(registrar));
                                } else
                                        /* Construction outside a fiber must keep the normal priority. */
                                        ASSERT_OK(new_event_future(type, e, fds[0], &f));

                                ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);
                                ASSERT_OK(new_event_future(type, e, fds[0], &probe));
                                ASSERT_OK(sd_future_set_priority(probe, probe_priority));

                                /* Both sources are ready. Inspect resolution directly, without callback
                                 * slots whose own priority inheritance could hide a constructor bug. */
                                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                                ASSERT_EQ(sd_future_state(f),
                                          priority < probe_priority ? SD_FUTURE_RESOLVED : SD_FUTURE_PENDING);
                                ASSERT_EQ(sd_future_state(probe),
                                          priority < probe_priority ? SD_FUTURE_PENDING : SD_FUTURE_RESOLVED);
                        }
}

TEST(event_source_inherit_fiber_priority_without_fiber) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int64_t priority;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_add_defer(e, &s, /* callback= */ NULL, /* userdata= */ NULL));
        ASSERT_OK(sd_event_source_set_priority(s, 42));
        ASSERT_OK(event_source_inherit_fiber_priority(s));
        ASSERT_OK(sd_event_source_get_priority(s, &priority));
        ASSERT_EQ(priority, 42);
}

TEST(future_new_defer_invalid) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;

        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_new_defer(/* e= */ NULL, 0, &f)), EINVAL);
        ASSERT_OK_ZERO(sd_event_default(/* ret= */ NULL));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_new_defer(SD_EVENT_DEFAULT, 0, &f)), ENOPKG);
        ASSERT_OK_ZERO(sd_event_default(/* ret= */ NULL));

        ASSERT_OK(sd_event_new(&e));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_new_defer(e, 0, /* ret= */ NULL)), EINVAL);
        ASSERT_NULL(f);
}

TEST(future_group_add_event) {
        bool timer;

        FOREACH_ARGUMENT(timer, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL;
                _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));

                if (timer)
                        ASSERT_OK(future_group_add_time_relative(group, CLOCK_MONOTONIC, 0, 1, 42));
                else {
                        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));
                        ASSERT_OK(future_group_add_io(group, pipefd[0], EPOLLIN));
                        ASSERT_OK_ZERO(sd_event_run(e, 0));
                        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);
                }

                ASSERT_EQ(sd_future_group_size(group), 1U);

                /* The helper must leave the child alive and uncancelled, with the group owning its
                 * only reference, until its event fires. */
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                ASSERT_OK(sd_event_loop(e));
                ASSERT_EQ(sd_future_result(group), timer ? 42 : (int) EPOLLIN);
        }
}

TEST(future_group_add_event_failure) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *group = NULL;
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        char c;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_cancel(group));
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);

        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_group_add_io(group, pipefd[0], EPOLLIN)), ESTALE);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(future_group_add_time_relative(group, CLOCK_MONOTONIC, 0, 1, 42)), ESTALE);

        /* Rejected children must leave no enabled sources behind, and releasing the IO child's
         * duplicate fd must not close the caller's fd. */
        ASSERT_OK_ZERO(sd_event_run(e, 0));
        ASSERT_OK_EQ_ERRNO(read(pipefd[0], &c, 1), 1);
        ASSERT_EQ(c, 'X');
}

static int timer_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        int *count = ASSERT_PTR(userdata);
        int r;

        (*count)++;

        r = sd_event_source_set_time_relative(s, 5 * USEC_PER_MSEC);
        if (r < 0)
                return r;

        if (sd_fiber_is_running() && *count >= 3)
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

static int event_run_fiber_func(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *inner_timer = NULL;
        int r;

        /* Create inner event loop from within the fiber */
        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Add a timer to the inner event loop that fires every 5ms */
        r = sd_event_add_time_relative(inner, &inner_timer, CLOCK_MONOTONIC,
                                       5 * USEC_PER_MSEC, 0, timer_callback,
                                       userdata);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(inner_timer, SD_EVENT_ON);
        if (r < 0)
                return r;

        return sd_event_loop(inner);
}

TEST(sd_event_loop_fiber) {
        /* Create outer event loop for the fiber scheduler */
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        /* Add a timer to the outer event loop that fires every 5ms */
        _cleanup_(sd_event_source_unrefp) sd_event_source *outer_timer = NULL;
        int outer_timer_count = 0;
        ASSERT_OK(sd_event_add_time_relative(outer, &outer_timer, CLOCK_MONOTONIC,
                                             5 * USEC_PER_MSEC, 0, timer_callback,
                                             &outer_timer_count));

        /* Create a fiber that will create and run the inner event loop */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int inner_timer_count = 0;
        ASSERT_OK(sd_fiber_new(outer, "event-runner", event_run_fiber_func, &inner_timer_count, /* destroy= */ NULL, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully */
        ASSERT_OK(sd_future_result(f));

        /* Both timers should have fired at least once */
        ASSERT_EQ(inner_timer_count, 3);
        ASSERT_GT(outer_timer_count, 0);
}

static int event_run_fiber_timeout_func(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        int r;

        /* Create inner event loop from within the fiber */
        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Run with a short timeout - should timeout since there are no events */
        return sd_event_run(inner, 10 * USEC_PER_MSEC);
}

TEST(sd_event_run_fiber_timeout) {
        /* Create outer event loop for the fiber scheduler */
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        /* Create a fiber that will run sd_event_run() with timeout */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "event-timeout", event_run_fiber_timeout_func, NULL, /* destroy= */ NULL, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully (timeout returns 0) */
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: sd_event_run() with zero timeout returns immediately */
static int sd_event_run_zero_timeout_fiber(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        int r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* With zero timeout on an empty event loop, should return 0 immediately */
        r = sd_event_run(inner, 0);
        if (r != 0)
                return r < 0 ? r : -EIO;

        return 0;
}

TEST(sd_event_run_zero_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "run-suspend-zero", sd_event_run_zero_timeout_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(outer));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: sd_event_run() dispatches immediately pending IO */
static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        char buf[64];

        (*counter)++;

        /* Drain the fd */
        (void) read(fd, buf, sizeof(buf));

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int sd_event_run_immediate_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int counter = 0, r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Add IO source watching the read end of the pipe */
        r = sd_event_add_io(inner, &source, pipefd[0], EPOLLIN, io_callback, &counter);
        if (r < 0)
                return r;

        /* Data is already available on the pipe (written before fiber started), so
         * sd_event_run() should dispatch immediately without suspending */
        r = sd_event_run(inner, USEC_INFINITY);
        if (r < 0)
                return r;

        /* The IO callback should have fired */
        if (counter != 1)
                return -EIO;

        return 0;
}

TEST(sd_event_run_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Write data before starting the fiber so it's immediately available */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "run-suspend-immediate", sd_event_run_immediate_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(outer));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: sd_event_run() with IO arriving during suspension */
static int sd_event_run_io_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int counter = 0, r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        r = sd_event_add_io(inner, &source, pipefd[0], EPOLLIN, io_callback, &counter);
        if (r < 0)
                return r;

        /* No data available yet, so this will suspend the fiber until IO arrives */
        r = sd_event_run(inner, USEC_INFINITY);
        if (r < 0)
                return r;

        if (counter != 1)
                return -EIO;

        return 0;
}

TEST(sd_event_run_io) {
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "run-suspend-io", sd_event_run_io_fiber, pipefd, /* destroy= */ NULL, &f));

        /* First iteration: fiber runs, adds IO source, suspends because no data */
        ASSERT_OK_POSITIVE(sd_event_run(outer, 0));

        /* Write data to the pipe to wake the inner event loop */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "Y", 1), 1);

        /* Complete: fiber resumes, dispatches IO, finishes */
        ASSERT_OK(sd_event_loop(outer));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: event_run called in a loop keeps event loop state consistent.
 * This is a regression test for a bug where error paths after sd_event_prepare()
 * could leave the inner event loop stuck in SD_EVENT_ARMED state. */
static int sd_event_run_loop_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int counter = 0, r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        r = sd_event_add_io(inner, &source, pipefd[0], EPOLLIN, io_callback, &counter);
        if (r < 0)
                return r;

        /* Call sd_event_run() multiple times with short timeouts.
         * Each call should leave the inner event loop in a clean state for the next call. */
        for (int i = 0; i < 5; i++) {
                r = sd_event_run(inner, 10 * USEC_PER_MSEC);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;
        }

        /* After multiple timeouts, the event loop should still be usable.
         * Write data and do one more run to verify. */
        if (counter == 0) {
                /* Data wasn't written yet, do a final run with longer timeout */
                r = sd_event_run(inner, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        if (counter != 1)
                return -EIO;

        return 0;
}

TEST(sd_event_run_loop) {
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "run-suspend-loop", sd_event_run_loop_fiber, pipefd, /* destroy= */ NULL, &f));

        /* Let the fiber run through a few timeout iterations */
        for (int i = 0; i < 10; i++)
                ASSERT_OK(sd_event_run(outer, 50 * USEC_PER_MSEC));

        /* Write data to unblock the fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "Z", 1), 1);

        ASSERT_OK(sd_event_loop(outer));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: sd_event_run() with an inner timer that fires during suspension */
static int inner_timer_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        (*counter)++;
        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int sd_event_run_timer_fiber(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int counter = 0, r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Add a timer that fires after 10ms */
        r = sd_event_add_time_relative(inner, &source, CLOCK_MONOTONIC,
                                       10 * USEC_PER_MSEC, 0, inner_timer_handler,
                                       &counter);
        if (r < 0)
                return r;

        /* Should suspend, then resume when the timer fires */
        r = sd_event_run(inner, USEC_INFINITY);
        if (r < 0)
                return r;

        if (counter != 1)
                return -EIO;

        return 0;
}

TEST(sd_event_run_timer) {
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(outer, "run-suspend-timer", sd_event_run_timer_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(outer));
        ASSERT_OK_ZERO(sd_future_result(f));
}

typedef struct EventRunInterruptedState {
        sd_event *inner;
        bool timeout;
        bool finite;
} EventRunInterruptedState;

static int event_run_interrupted_fiber(void *userdata) {
        EventRunInterruptedState *s = ASSERT_PTR(userdata);

        SD_FIBER_TIMEOUT(s->timeout ? 5 * USEC_PER_MSEC : USEC_INFINITY);
        return sd_event_run(s->inner, s->finite ? USEC_PER_MINUTE : USEC_INFINITY);
}

TEST(sd_event_run_interrupted) {
        bool timeout, finite;

        FOREACH_ARGUMENT(timeout, false, true)
                FOREACH_ARGUMENT(finite, false, true) {
                        _cleanup_(sd_event_unrefp) sd_event *outer = NULL, *inner = NULL;
                        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
                        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
                        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
                        int count = 0;

                        ASSERT_OK(sd_event_new(&outer));
                        ASSERT_OK(sd_event_new(&inner));
                        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));
                        ASSERT_OK(sd_event_add_io(inner, &source, pipefd[0], EPOLLIN, io_callback, &count));

                        EventRunInterruptedState s = { .inner = inner, .timeout = timeout, .finite = finite };
                        ASSERT_OK(sd_fiber_new(outer, "event-interrupted", event_run_interrupted_fiber, &s,
                                               /* destroy= */ NULL, &f));
                        ASSERT_OK_POSITIVE(sd_event_run(outer, 0));
                        ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);
                        if (!timeout)
                                ASSERT_OK(sd_future_cancel(f));

                        while (sd_future_state(f) == SD_FUTURE_PENDING)
                                ASSERT_OK_POSITIVE(sd_event_run(outer, USEC_INFINITY));
                        ASSERT_EQ(sd_future_result(f), timeout ? -ETIME : -ECANCELED);
                        ASSERT_EQ(count, 0);

                        /* Cleanup must remove the outer loop's IO watcher and optional timer. Making
                         * the inner fd readable must not dispatch anything on the outer loop, while
                         * the inner loop itself remains usable after the interrupted run. */
                        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);
                        ASSERT_OK_ZERO(sd_event_run(outer, 0));
                        ASSERT_OK_POSITIVE(sd_event_run(inner, 0));
                        ASSERT_EQ(count, 1);

                        int inner_fd = ASSERT_OK(sd_event_get_fd(inner));
                        int outer_fd = ASSERT_OK(sd_event_get_fd(outer));
                        f = sd_future_unref(f);
                        source = sd_event_source_unref(source);
                        inner = sd_event_unref(inner);
                        outer = sd_event_unref(outer);

                        /* A leaked future or slot would keep its event loop and epoll fd alive. */
                        ASSERT_ERROR_ERRNO(fcntl(inner_fd, F_GETFD), EBADF);
                        ASSERT_ERROR_ERRNO(fcntl(outer_fd, F_GETFD), EBADF);
                }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
