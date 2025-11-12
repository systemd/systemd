/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <signal.h>

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "sd-event.h"
#include "sd-future.h"

#include "log-context.h"
#include "memory-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"
#include "time-util.h"

static int simple_fiber(void *userdata) {
        int *value = ASSERT_PTR(userdata);
        return *value;
}

TEST(fiber_simple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 5;
        ASSERT_OK(sd_fiber_new(e, "simple", simple_fiber, &value, NULL, &f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(f), 5);
}

/* Fiber that yields once */
static int yielding_fiber(void *userdata) {
        int *counter = userdata;
        (*counter)++;

        sd_fiber_yield();

        (*counter)++;
        return 0;
}

/* Test: Single fiber that yields */
TEST(fiber_single_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "yielding", yielding_fiber, &counter, NULL, &f));

        /* First iteration: fiber runs until first yield */
        ASSERT_EQ(counter, 0);
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counter, 1);

        /* Second iteration: fiber runs from yield to completion */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counter, 2);

        /* No more fibers to run */
        ASSERT_OK_ZERO(sd_event_loop(e));
}

static int counting_fiber(void *userdata) {
        int counter = 0;

        for (int i = 0; i < 5; i++) {
                counter++;
                sd_fiber_yield();
        }

        return counter;
}

/* Test: Multiple fibers yielding cooperatively */
TEST(fiber_multiple_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[5] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "counting-%zu", i));
                ASSERT_OK(sd_fiber_new(e, name, counting_fiber, NULL, NULL, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK_EQ(sd_future_result(fibers[i]), 5);
}

static int priority_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);

        (*counter)++;
        sd_fiber_yield();

        return *counter;
}

/* Test: Priority-based scheduling */
TEST(fiber_priority_ascending) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[5] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);
        int counter = 0;

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_fiber_new(e, name, priority_fiber, &counter, NULL, &fibers[i]));
                ASSERT_OK(sd_future_set_priority(fibers[i], i));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have ascending priorities, so we the first one to run to completion,
         * followed by the second one, etc. */

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_EQ(sd_future_result(fibers[i]), (int) i + 1);
}

TEST(fiber_priority_identical) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[5] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);
        int counter = 0;

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_fiber_new(e, name, priority_fiber, &counter, NULL, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have the same priorities, so we expect all of them to run once first, and then they'll
         * all run again another time, so they should all return the same value. */

        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_EQ(sd_future_result(fibers[i]), (int) 5);
}

static int error_fiber(void *userdata) {
        return -ENOENT;
}

TEST(fiber_error_return) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "error", error_fiber, NULL, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(f), -ENOENT);
}

static int cancel_fiber(void *userdata) {
        return sd_fiber_yield();
}

TEST(fiber_cancel_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 42;
        ASSERT_OK(sd_fiber_new(e, "cancel", cancel_fiber, &value, NULL, &f));

        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
}

static int fiber_that_yields(void *userdata) {
        int *yield_count = userdata;
        int r;

        for (int i = 0; i < 5; i++) {
                (*yield_count)++;
                r = sd_fiber_yield();
                if (r < 0)
                        return r;  /* Propagate cancellation error */
        }

        return 0;
}

/* Test: fiber_yield() returns error when fiber is cancelled externally */
TEST(fiber_cancel_propagation_via_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int yield_count = 0;
        ASSERT_OK(sd_fiber_new(e, "yielding", fiber_that_yields, &yield_count, NULL, &f));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 1);
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 2);

        ASSERT_OK(sd_future_cancel(f));

        ASSERT_OK(sd_event_loop(e));

        /* sd_fiber should have been cancelled */
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_EQ(yield_count, 2);
}

/* Test: Cancel a fiber that has already completed */
TEST(fiber_cancel_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 42;
        ASSERT_OK(sd_fiber_new(e, "simple", simple_fiber, &value, NULL, &f));

        /* Run the fiber to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Canceling a completed fiber should be a no-op */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_EQ(sd_future_result(f), 42);
}

static int multiple_yield_fiber(void *userdata) {
        int *counter = userdata;
        int r;

        for (int i = 0; i < 3; i++) {
                (*counter)++;
                r = sd_fiber_yield();
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Test: Cancel one fiber among multiple */
TEST(fiber_cancel_one_of_many) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[3] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);
        int counters[3] = {0, 0, 0};
        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK(sd_fiber_new(e, "multiple-yield", multiple_yield_fiber, &counters[i], NULL, &fibers[i]));

        /* Run one iteration - all fibers yield after incrementing once */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counters[0], 1);
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(counters[2], 1);

        /* Cancel the second fiber */
        ASSERT_OK(sd_future_cancel(fibers[1]));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* First and third fibers should complete normally */
        ASSERT_EQ(counters[0], 3);
        ASSERT_EQ(counters[2], 3);
        ASSERT_EQ(sd_future_result(fibers[0]), 0);
        ASSERT_EQ(sd_future_result(fibers[2]), 0);

        /* Second fiber should be canceled with counter at 1 */
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(sd_future_result(fibers[1]), -ECANCELED);
}

/* Test: sd_fiber_await() - wait for a fiber to complete */
static int slow_fiber(void *userdata) {
        int *counter = userdata;

        for (int i = 0; i < 3; i++) {
                (*counter)++;
                sd_fiber_yield();
        }

        return 42;
}

static int waiting_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        r = sd_future_result(target);
        return r == 42 ? 0 : -EIO;
}

TEST(fiber_wait_for_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create target fiber with lower priority (runs second) */
        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "slow", slow_fiber, &counter, NULL, &target));
        ASSERT_OK(sd_future_set_priority(target, 1));

        /* Create waiter fiber with higher priority (runs first) */
        ASSERT_OK(sd_fiber_new(e, "waiting", waiting_fiber, target, NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(waiter));
        ASSERT_OK_EQ(sd_future_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: wait for already completed fiber */
static int wait_for_completed_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int value = 100;

        /* Create target fiber with higher priority (runs first) */
        ASSERT_OK(sd_fiber_new(e, "simple", simple_fiber, &value, NULL, &target));
        ASSERT_OK(sd_future_set_priority(target, 0));
        /* Create waiter fiber with lower priority (runs second, after target completes) */
        ASSERT_OK(sd_fiber_new(e, "wait-for-completed", wait_for_completed_fiber, target, NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 1));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(waiter), 100);
        ASSERT_OK_EQ(sd_future_result(target), 100);
}

/* Test: wait for cancelled fiber */
static int wait_for_cancelled_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_cancelled) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "yielding", fiber_that_yields, &counter, NULL, &target));
        ASSERT_OK(sd_fiber_new(e, "wait-for-cancelled", wait_for_cancelled_fiber, target, NULL, &waiter));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        ASSERT_OK(sd_future_cancel(target));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_ERROR(sd_future_result(waiter), ECANCELED);
        ASSERT_ERROR(sd_future_result(target), ECANCELED);
}

/* Test: multiple fibers waiting for the same target */
static int multi_waiter_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_multiple_waiters) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "slow", slow_fiber, &counter, NULL, &target));

        sd_future *waiters[3] = {};
        CLEANUP_ELEMENTS(waiters, sd_future_unref_array_clear);
        for (size_t i = 0; i < ELEMENTSOF(waiters); i++)
                ASSERT_OK(sd_fiber_new(e, "multi-waiter", multi_waiter_fiber, target, NULL, &waiters[i]));

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < ELEMENTSOF(waiters); i++)
                ASSERT_OK_EQ(sd_future_result(waiters[i]), 42);

        ASSERT_OK_EQ(sd_future_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: chain of waiting fibers */
static int chain_waiter_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        r = sd_future_result(target);
        return r + 1;
}

TEST(fiber_wait_for_chain) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[5] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);
        int value = 10;

        ASSERT_OK(sd_fiber_new(e, "simple", simple_fiber, &value, NULL, &fibers[0]));

        /* Each subsequent fiber waits for the previous and adds 1 */
        for (size_t i = 1; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK(sd_fiber_new(e, "chain-waiter", chain_waiter_fiber, fibers[i - 1], NULL, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* Check results: 10, 11, 12, 13, 14 */
        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK_EQ(sd_future_result(fibers[i]), 10 + (int) i);
}

static int nested_run_inner_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);

        (*counter)++;
        int r = sd_fiber_yield();
        if (r < 0)
                return r;
        (*counter)++;

        return 0;
}

static int nested_run_outer_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_future_unrefp) sd_future *nested = NULL;
        int r;

        /* Yield once before the nested loop: this forces the outer fiber to later resume through its own
         * siglongjmp back to its resume_context after the inner fiber_run() has executed, which is
         * exactly the path that breaks when the resume context is stored thread-globally instead of
         * per-fiber. */
        r = sd_fiber_yield();
        if (r < 0)
                return r;

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        r = sd_event_set_exit_on_idle(inner, true);
        if (r < 0)
                return r;

        /* Spawn a fiber on the inner event loop. Driving it via sd_event_loop(inner) causes fiber_run() to
         * be invoked while we are already executing inside fiber_run() for the outer fiber. */
        r = sd_fiber_new(inner, "inner", nested_run_inner_fiber, counter, NULL, &nested);
        if (r < 0)
                return r;

        r = sd_event_loop(inner);
        if (r < 0)
                return r;

        r = sd_future_result(nested);
        if (r < 0)
                return r;

        /* Yield again after the inner loop has returned. If the outer fiber's resume context was clobbered
         * by the nested fiber_run(), the siglongjmp underneath this yield would jump into an already
         * unwound stack frame. */
        return sd_fiber_yield();
}

TEST(fiber_nested_run) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "outer", nested_run_outer_fiber, &counter, NULL, &outer));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(outer));

        /* The inner fiber incremented the counter once before yielding and once after resuming. */
        ASSERT_EQ(counter, 2);
}

static int nested_current_check_inner_fiber(void *userdata) {
        sd_future **slots = ASSERT_PTR(userdata);

        slots[1] = sd_fiber_get_current();
        int r = sd_fiber_yield();
        if (r < 0)
                return r;
        /* After resuming, the current fiber must still be us, not the outer fiber that was current when
         * fiber_run() re-entered. */
        if (sd_fiber_get_current() != slots[1])
                return -EBADF;

        return 0;
}

static int nested_current_check_outer_fiber(void *userdata) {
        sd_future **slots = ASSERT_PTR(userdata);
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_future_unrefp) sd_future *nested = NULL;
        int r;

        slots[0] = sd_fiber_get_current();

        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        r = sd_event_set_exit_on_idle(inner, true);
        if (r < 0)
                return r;

        r = sd_fiber_new(inner, "inner", nested_current_check_inner_fiber, slots, NULL, &nested);
        if (r < 0)
                return r;

        r = sd_event_loop(inner);
        if (r < 0)
                return r;

        r = sd_future_result(nested);
        if (r < 0)
                return r;

        /* After the nested fiber_run() has returned, the current fiber must have been restored to the
         * outer fiber rather than left as NULL or pointing at the (now freed) inner fiber. */
        if (sd_fiber_get_current() != slots[0])
                return -EBADF;

        return 0;
}

TEST(fiber_nested_run_current_restored) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *slots[2] = {};
        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        ASSERT_OK(sd_fiber_new(e, "outer", nested_current_check_outer_fiber, slots, NULL, &outer));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(outer));

        ASSERT_NOT_NULL(slots[0]);
        ASSERT_NOT_NULL(slots[1]);
        ASSERT_TRUE(slots[0] != slots[1]);
}

static int nested_cancellation_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *nested = NULL;
        int r;

        if (*counter >= 5)
                return sd_fiber_sleep(10 * USEC_PER_SEC);

        (*counter)++;

        _cleanup_free_ char *name = NULL;
        if (asprintf(&name, "nested-cancellation-%i", *counter) < 0)
                return -ENOMEM;

        /* Create a nested fiber within this fiber */
        r = sd_fiber_new(sd_fiber_get_event(), name, nested_cancellation_fiber, counter, NULL, &nested);
        if (r < 0)
                return r;

        /* Wait for the nested fiber to complete */
        r = sd_fiber_await(nested);
        if (r < 0)
                return r;

        /* If we got here without cancellation, verify the nested fiber completed */
        return sd_future_result(nested);
}

static int exit_loop_fiber(void *userdata) {
        /* Just exit the event loop, causing the outer fiber to be cancelled */
        return sd_event_exit(sd_fiber_get_event(), 0);
}

TEST(fiber_nested_cancellation) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        int counter = 0;

        /* Create outer fiber with higher priority (runs first) */
        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        ASSERT_OK(sd_fiber_new(e, "outer", nested_cancellation_fiber, &counter, NULL, &outer));

        /* Create exit fiber with lower priority (runs after all nested fibers have suspended) */
        _cleanup_(sd_future_unrefp) sd_future *exit_fiber = NULL;
        ASSERT_OK(sd_fiber_new(e, "exit-loop", exit_loop_fiber, NULL, NULL, &exit_fiber));
        ASSERT_OK(sd_future_set_priority(exit_fiber, 1));

        /* Run the event loop - the exit fiber should cause it to exit,
         * which should cancel the outer fiber, which should cancel the nested fiber, and so forth. */
        ASSERT_OK(sd_event_loop(e));

        /* The exit fiber should have completed successfully */
        ASSERT_OK(sd_future_result(exit_fiber));

        /* The outer fiber should have been cancelled */
        ASSERT_ERROR(sd_future_result(outer), ECANCELED);

        /* The nested fiber was created and incremented counter once before being cancelled */
        ASSERT_GT(counter, 0);
}

static int nested_fiber_cleanup_nested_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        int r;

        r = sd_fiber_sleep(10 * USEC_PER_SEC);
        if (r == -ECANCELED)
                (*counter)++;
        else if (r < 0)
                return r;

        return 0;
}

static int nested_fiber_cleanup_fiber(void *userdata) {
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *nested = NULL;
        int r;

        /* Create a nested fiber within this fiber. */
        r = sd_fiber_new(sd_fiber_get_event(), "nested", nested_fiber_cleanup_nested_fiber, userdata, NULL, &nested);
        if (r < 0)
                return r;

        /* Yield and then exit, the nested fiber should be cancelled. */
        return sd_fiber_yield();
}

TEST(nested_fiber_cleanup) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "outer", nested_fiber_cleanup_fiber, &counter, NULL, &outer));

        ASSERT_OK(sd_event_loop(e));

        /* The outer fiber should have finished normally */
        ASSERT_OK(sd_future_result(outer));

        /* The nested fiber was created and incremented its counter once when it was cancelled. */
        ASSERT_GT(counter, 0);
}

static int priority_check_fiber(void *userdata) {
        int64_t *ret = ASSERT_PTR(userdata);

        /* Verify that sd_fiber_get_priority() returns the value set via sd_future_set_priority() */
        *ret = sd_fiber_get_priority();

        /* Exercise sd_fiber_sleep() which internally creates a time future. This verifies that the priority
         * is correctly propagated to the time event source (via f->time.source, not f->io.source). */
        return sd_fiber_sleep(1);
}

TEST(fiber_priority_get) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        int64_t got_priority = 0;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "priority-check", priority_check_fiber, &got_priority, NULL, &f));
        ASSERT_OK(sd_future_set_priority(f, 10));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));

        /* Verify priority was stored and retrievable */
        ASSERT_EQ(got_priority, 10);
}

static int floating_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);

        (*counter)++;
        int r = sd_fiber_yield();
        if (r < 0)
                return r;
        (*counter)++;

        return 0;
}

TEST(fiber_floating) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "floating", floating_fiber, &counter, NULL, &f));

        ASSERT_OK_ZERO(sd_fiber_get_floating(f));
        ASSERT_OK(sd_fiber_set_floating(f, true));
        ASSERT_OK_POSITIVE(sd_fiber_get_floating(f));

        /* Drop our handle: the floating ref keeps the future alive until the fiber resolves, after
         * which the self-unref frees it. If this didn't work we'd either leak (visible under ASan) or
         * trip fiber_free()'s "state == COMPLETED" assertion. */
        f = sd_future_unref(f);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(counter, 2);
}

static int drop_extra_ref(sd_future *f) {
        /* Drop an extra ref the test installed before the callback fires. After this returns, the
         * floating self-ref is the only thing keeping the future alive — exercising the path where
         * the floating unref in fiber_run() is the last unref. */
        sd_future_unref(f);
        return 0;
}

TEST(fiber_floating_callback_drops_ref) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "floating-cb", floating_fiber, &counter, NULL, &f));

        ASSERT_OK(sd_fiber_set_floating(f, true));

        /* Bump the ref for the callback to drop, then install the callback. */
        sd_future_ref(f);
        ASSERT_OK(sd_future_set_callback(f, drop_extra_ref, NULL));

        /* Drop our handle. Refs remaining: floating self-ref + the extra ref the callback will drop. */
        f = sd_future_unref(f);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(counter, 2);
}

TEST(fiber_floating_toggle) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new(e, "floating-toggle", floating_fiber, &counter, NULL, &f));

        /* Toggling floating on and off again should leave the refcount unchanged: set_floating(true)
         * takes a ref and set_floating(false) drops it. If the accounting were off, the subsequent
         * event loop would either free the future while the fiber still runs (fiber_free assertion)
         * or leak it. */
        ASSERT_OK(sd_fiber_set_floating(f, true));
        ASSERT_OK(sd_fiber_set_floating(f, false));
        ASSERT_OK_ZERO(sd_fiber_get_floating(f));

        /* Setting floating to the same value twice should be a no-op. */
        ASSERT_OK(sd_fiber_set_floating(f, false));
        ASSERT_OK(sd_fiber_set_floating(f, true));
        ASSERT_OK(sd_fiber_set_floating(f, true));

        /* Drop our handle; the still-floating ref drives cleanup. */
        f = sd_future_unref(f);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(counter, 2);
}

/* Test: SD_FIBER_TIMEOUT scope expires while the fiber is suspended with no other wakeup source. */
static int timeout_suspend_fiber(void *userdata) {
        SD_FIBER_TIMEOUT(50 * USEC_PER_MSEC);

        /* Plain suspend with no other future to wake us — only the deadline timer can resume. */
        return sd_fiber_suspend();
}

TEST(fiber_timeout_suspend_expires) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "timeout-suspend", timeout_suspend_fiber, NULL, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ETIME);
}

/* Test: SD_FIBER_TIMEOUT scope around a sleep that finishes before the deadline expires; the
 * cleanup must cancel the timer cleanly without leaving a stale wakeup. */
static int timeout_in_time_fiber(void *userdata) {
        SD_FIBER_TIMEOUT(1 * USEC_PER_SEC);
        return sd_fiber_sleep(10 * USEC_PER_MSEC);
}

TEST(fiber_timeout_sleep_in_time) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "in-time", timeout_in_time_fiber, NULL, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: SD_FIBER_TIMEOUT(USEC_INFINITY) is a no-op — no timer is created and the fiber completes
 * normally. */
static int timeout_infinite_fiber(void *userdata) {
        SD_FIBER_TIMEOUT(USEC_INFINITY);
        return sd_fiber_sleep(10 * USEC_PER_MSEC);
}

TEST(fiber_timeout_infinite_no_op) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "infinite", timeout_infinite_fiber, NULL, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(f));
}

/* Test: SD_FIBER_WITH_TIMEOUT block form returns -ETIME from the suspend inside it. */
static int with_timeout_block_fiber(void *userdata) {
        int r = 0;
        SD_FIBER_WITH_TIMEOUT(50 * USEC_PER_MSEC)
                r = sd_fiber_suspend();
        return r;
}

TEST(fiber_with_timeout_block) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "with-timeout", with_timeout_block_fiber, NULL, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ETIME);
}

/* Test: nested SD_FIBER_TIMEOUT — inner scope's timer fires first; once we're back in just the
 * outer scope, suspending again must time out via the still-armed outer timer. */
static int nested_timeout_fiber(void *userdata) {
        int *fired = ASSERT_PTR(userdata);

        SD_FIBER_TIMEOUT(50 * USEC_PER_MSEC); /* outer */

        SD_FIBER_WITH_TIMEOUT(20 * USEC_PER_MSEC) { /* inner — expires first */
                int r = sd_fiber_suspend();
                if (r != -ETIME)
                        return -ENOTRECOVERABLE;
                (*fired)++;
        }

        /* Inner scope is gone, but the outer timer is still armed (it only used ~20ms of its
         * 100ms budget). Suspending again must eventually wake us with -ETIME. */
        int r = sd_fiber_suspend();
        if (r != -ETIME)
                return -ENOTRECOVERABLE;
        (*fired)++;

        return 0;
}

TEST(fiber_timeout_nested) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        int fired = 0;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "nested-timeout", nested_timeout_fiber, &fired, NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(f));
        ASSERT_EQ(fired, 2);
}

/* Test: signal mask is per-thread, not per-fiber. Changes one fiber makes via pthread_sigmask
 * must be visible to other fibers on the same thread, both while the modifying fiber is
 * suspended and after it resumes. The fiber switch (sigsetjmp/siglongjmp with savesigs=0)
 * deliberately doesn't save or restore the mask. */
static int sigmask_peer_fiber(void *userdata) {
        sigset_t set, current;

        /* The waiter blocked SIGUSR1 before await'ing us; the per-thread mask should still
         * have it blocked here. */
        ASSERT_OK_ZERO(-pthread_sigmask(SIG_SETMASK, NULL, &current));
        ASSERT_TRUE(sigismember(&current, SIGUSR1));

        ASSERT_OK(sigemptyset(&set));
        ASSERT_OK(sigaddset(&set, SIGUSR1));
        ASSERT_OK_ZERO(-pthread_sigmask(SIG_UNBLOCK, &set, NULL));

        return 0;
}

static int sigmask_waiter_fiber(void *userdata) {
        sd_future *peer = ASSERT_PTR(userdata);
        sigset_t set, current;

        ASSERT_OK(sigemptyset(&set));
        ASSERT_OK(sigaddset(&set, SIGUSR1));
        ASSERT_OK_ZERO(-pthread_sigmask(SIG_BLOCK, &set, NULL));

        ASSERT_OK_ZERO(-pthread_sigmask(SIG_SETMASK, NULL, &current));
        ASSERT_TRUE(sigismember(&current, SIGUSR1));

        int r = sd_fiber_await(peer);
        if (r < 0)
                return r;

        /* The peer unblocked SIGUSR1 while we were suspended. The change is per-thread, so
         * we must observe it here. */
        ASSERT_OK_ZERO(-pthread_sigmask(SIG_SETMASK, NULL, &current));
        ASSERT_FALSE(sigismember(&current, SIGUSR1));

        return 0;
}

TEST(fiber_signal_mask_is_per_thread) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sigset_t saved;
        ASSERT_OK_ZERO(-pthread_sigmask(SIG_SETMASK, NULL, &saved));

        _cleanup_(sd_future_unrefp) sd_future *waiter = NULL, *peer = NULL;
        ASSERT_OK(sd_fiber_new(e, "sigmask-peer", sigmask_peer_fiber, NULL, NULL, &peer));
        ASSERT_OK(sd_future_set_priority(peer, 1));
        ASSERT_OK(sd_fiber_new(e, "sigmask-waiter", sigmask_waiter_fiber, peer, NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 0));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(waiter));
        ASSERT_OK(sd_future_result(peer));

        ASSERT_OK_ZERO(-pthread_sigmask(SIG_SETMASK, &saved, NULL));
}

/* Test: log context is per-fiber. fiber_run() swaps the thread-local log context (and prefix) with
 * a per-fiber stash on entry and exit, so fields pushed by one fiber must not leak into another
 * fiber that runs while the first is suspended, and must be restored when the first resumes. */
static int log_context_peer_fiber(void *userdata) {
        size_t *peer_observed = ASSERT_PTR(userdata);

        /* The waiter pushed a field before await'ing us. If log context were shared across fibers,
         * we would observe it here. Record what we see and let the caller verify. */
        *peer_observed = log_context_num_fields();

        return 0;
}

static int log_context_waiter_fiber(void *userdata) {
        sd_future *peer = ASSERT_PTR(userdata);

        size_t before_push = log_context_num_fields();

        LOG_CONTEXT_PUSH("WAITER=here");
        size_t after_push = log_context_num_fields();
        if (after_push != before_push + 1)
                return -EBADF;

        int r = sd_fiber_await(peer);
        if (r < 0)
                return r;

        /* Our pushed field must be visible again after the peer ran and resumed us. */
        if (log_context_num_fields() != after_push)
                return -EBADF;

        return 0;
}

TEST(fiber_log_context_per_fiber) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        size_t baseline = log_context_num_fields();

        size_t peer_observed = 0;
        _cleanup_(sd_future_unrefp) sd_future *waiter = NULL, *peer = NULL;
        ASSERT_OK(sd_fiber_new(e, "log-peer", log_context_peer_fiber, &peer_observed, NULL, &peer));
        ASSERT_OK(sd_future_set_priority(peer, 1));
        ASSERT_OK(sd_fiber_new(e, "log-waiter", log_context_waiter_fiber, peer, NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 0));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(waiter));
        ASSERT_OK(sd_future_result(peer));

        /* Inside the peer, only the peer's own FIBER= field (pushed by fiber_run) should have been
         * active — the waiter's WAITER= push must have been swapped out. */
        ASSERT_EQ(peer_observed, baseline + 1);

        /* The thread-local log context should be exactly as it was before the test ran. */
        ASSERT_EQ(log_context_num_fields(), baseline);
}

static int stack_overflow_fiber(void *userdata) {
        volatile char anchor;
        size_t pagesz = page_size();

        /* Walk one page at a time below the fiber's current SP, writing one byte per page,
         * until the kernel raises a fatal signal — either by hitting the guard page at the
         * base of the fiber's mapping (downward stacks) or by walking off the end of the
         * mapping into unmapped memory (upward stacks like hppa, where SP starts near the
         * low end). The 64 MiB ceiling is purely a safety net so the test fails loudly
         * instead of looping if the guard isn't there. */
        for (size_t i = 1; i < (64U * U64_MB) / pagesz; i++) {
                volatile char *p = (volatile char *) ((uintptr_t) &anchor - i * pagesz);
                *p = 0;
        }
        return 0;
}

TEST(fiber_stack_guard) {
#if HAS_FEATURE_ADDRESS_SANITIZER
        (void) log_tests_skipped("ASan intercepts deliberate stack OOB writes");
        return;
#endif
#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND) {
                (void) log_tests_skipped("Valgrind intercepts deliberate stack OOB writes");
                return;
        }
#endif

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r = pidref_safe_fork("(stack-overflow)", FORK_RESET_SIGNALS|FORK_LOG, &pidref);
        ASSERT_OK(r);

        if (r == 0) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));

                _cleanup_(sd_future_unrefp) sd_future *f = NULL;
                ASSERT_OK(sd_fiber_new(e, "overflow", stack_overflow_fiber, NULL, NULL, &f));
                (void) sd_event_loop(e);
                _exit(EXIT_SUCCESS);    /* unreachable if the guard fires */
        }

        siginfo_t si;
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_TRUE(IN_SET(si.si_code, CLD_KILLED, CLD_DUMPED));
        ASSERT_TRUE(IN_SET(si.si_status, SIGSEGV, SIGBUS));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
