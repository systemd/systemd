/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "fd-util.h"
#include "tests.h"
#include "time-util.h"

TEST(future_group_add_event) {
        bool timer;

        FOREACH_ARGUMENT(timer, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL;
                _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
                size_t size;

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

                ASSERT_OK(sd_future_group_size(group, &size));
                ASSERT_EQ(size, 1U);

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

DEFINE_TEST_MAIN(LOG_DEBUG);
