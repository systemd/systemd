/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "tests.h"

/* Body for "I exist to be cancelled" siblings: suspends until something cancels us. */
static int suspend_fiber(void *userdata) {
        return sd_fiber_suspend();
}

/* Body for "let other things make progress before I return": yields once (giving the event
 * loop a chance to dispatch other pending sources) then returns the configured result.
 * Useful for sequencing without a real timer — sd-event dispatches at the same priority by
 * pending iteration, so a rearmed source goes to the back of the queue. */
static int yield_then_return_fiber(void *userdata) {
        int *result = ASSERT_PTR(userdata);
        int r = sd_fiber_yield();
        if (r < 0)
                return r;
        return *result;
}

TEST(future_group_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        uint64_t policy;

        ASSERT_OK(sd_event_new(&e));

        FOREACH_ARGUMENT(policy, SD_FUTURE_GROUP_WAIT_ALL, SD_FUTURE_GROUP_WAIT_ANY,
                         SD_FUTURE_GROUP_IGNORE_ERRORS,
                         SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS) {
                _cleanup_(sd_future_unrefp) sd_future *group = NULL;

                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_group_set_policy(group, policy));
                ASSERT_OK_ZERO(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);
                ASSERT_EQ(sd_future_group_size(group), 0U);

                ASSERT_OK(sd_future_cancel(group));
                ASSERT_EQ(sd_future_state(group), SD_FUTURE_RESOLVED);
                ASSERT_ERROR(sd_future_result(group), ECANCELED);
                ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_set_policy(group, policy)), ESTALE);
        }
}

TEST(future_group_size) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *first = NULL, *second = NULL;

        ASSERT_EQ(sd_future_group_size(/* f= */ NULL), 0U);

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_EQ(sd_future_group_size(group), 0U);

        ASSERT_OK(sd_future_new_defer(e, 0, &first));
        ASSERT_OK(sd_future_new_defer(e, 0, &second));
        ASSERT_EQ(ASSERT_RETURN_EXPECTED(sd_future_group_size(first)), 0U);

        ASSERT_OK(sd_future_group_add(group, first));
        ASSERT_EQ(sd_future_group_size(group), 1U);
        ASSERT_OK(sd_future_group_add(group, second));
        ASSERT_EQ(sd_future_group_size(group), 2U);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(group));
        ASSERT_EQ(sd_future_group_size(group), 2U);
}

/* Distinct errors pin down selection by insertion order when multiple children have settled
 * before the group's callbacks run, including when completion order is reversed. */
TEST(future_group_first_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        uint64_t policy;

        ASSERT_OK(sd_event_new(&e));

        FOREACH_ARGUMENT(policy, SD_FUTURE_GROUP_WAIT_ALL, SD_FUTURE_GROUP_WAIT_ANY,
                         SD_FUTURE_GROUP_IGNORE_ERRORS,
                         SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS) {
                _cleanup_(sd_future_unrefp) sd_future *group = NULL, *a = NULL, *b = NULL;

                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_group_set_policy(group, policy));
                ASSERT_OK(sd_future_group_new(e, &a));
                ASSERT_OK(sd_future_group_new(e, &b));
                ASSERT_OK(sd_future_group_add_many(group, a, b));
                ASSERT_OK(sd_future_resolve(b, -EIO));
                ASSERT_OK(sd_future_resolve(a, -EINVAL));

                while (sd_future_state(group) == SD_FUTURE_PENDING)
                        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

                ASSERT_ERROR(sd_future_result(group), EINVAL);
        }
}

/* WAIT_ALL happy path: three children all succeed. */
TEST(future_group_wait_all_happy) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *c1 = NULL, *c2 = NULL, *c3 = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_new_defer(e, 0, &c1));
        ASSERT_OK(sd_future_new_defer(e, 0, &c2));
        ASSERT_OK(sd_future_new_defer(e, 0, &c3));
        ASSERT_OK(sd_future_group_add(group, c1));
        ASSERT_OK(sd_future_group_add(group, c2));
        ASSERT_OK(sd_future_group_add(group, c3));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(group));
        ASSERT_OK_ZERO(sd_future_result(c1));
        ASSERT_OK_ZERO(sd_future_result(c2));
        ASSERT_OK_ZERO(sd_future_result(c3));
}

/* WAIT_ALL fail-fast (default): one child errors fast, others sleeping; group resolves with
 * that error, sleepers observe -ECANCELED. */
TEST(future_group_wait_all_fail_fast) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL, *sleeper_a = NULL, *sleeper_b = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &errorer));
        ASSERT_OK(sd_fiber_new(e, "sleep-a", suspend_fiber, NULL, NULL, &sleeper_a));
        ASSERT_OK(sd_fiber_new(e, "sleep-b", suspend_fiber, NULL, NULL, &sleeper_b));

        ASSERT_OK(sd_future_group_add(group, errorer));
        ASSERT_OK(sd_future_group_add(group, sleeper_a));
        ASSERT_OK(sd_future_group_add(group, sleeper_b));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), EINVAL);
        ASSERT_ERROR(sd_future_result(errorer), EINVAL);
        ASSERT_ERROR(sd_future_result(sleeper_a), ECANCELED);
        ASSERT_ERROR(sd_future_result(sleeper_b), ECANCELED);
}

/* WAIT_ALL with IGNORE_ERRORS: one child errors, others succeed; everyone runs to completion;
 * group resolves with the first error. */
TEST(future_group_wait_all_ignore_errors) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL, *succeeder = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &errorer));
        ASSERT_OK(sd_future_new_defer(e, 0, &succeeder));
        ASSERT_OK(sd_future_group_add(group, errorer));
        ASSERT_OK(sd_future_group_add(group, succeeder));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), EINVAL);
        ASSERT_ERROR(sd_future_result(errorer), EINVAL);
        ASSERT_OK_ZERO(sd_future_result(succeeder));
}

/* WAIT_ANY: three sleepers with different durations; group resolves with shortest sleeper's
 * result; siblings observe -ECANCELED. */
TEST(future_group_wait_any) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *fast = NULL, *medium = NULL, *slow = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));

        ASSERT_OK(sd_future_new_defer(e, 42, &fast));
        ASSERT_OK(sd_fiber_new(e, "medium", suspend_fiber, NULL, NULL, &medium));
        ASSERT_OK(sd_fiber_new(e, "slow", suspend_fiber, NULL, NULL, &slow));
        ASSERT_OK(sd_future_group_add(group, fast));
        ASSERT_OK(sd_future_group_add(group, medium));
        ASSERT_OK(sd_future_group_add(group, slow));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(group), 42);
        ASSERT_EQ(sd_future_result(fast), 42);
        ASSERT_ERROR(sd_future_result(medium), ECANCELED);
        ASSERT_ERROR(sd_future_result(slow), ECANCELED);
}

TEST(future_group_wait_any_mixed_outcomes) {
        bool success_first, resolve_success_first;

        FOREACH_ARGUMENT(success_first, false, true)
                FOREACH_ARGUMENT(resolve_success_first, false, true) {
                        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *success = NULL, *error = NULL;

                        ASSERT_OK(sd_event_new(&e));
                        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                        ASSERT_OK(sd_future_group_new(e, &group));
                        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));
                        ASSERT_OK(sd_future_group_new(e, &success));
                        ASSERT_OK(sd_future_group_new(e, &error));
                        ASSERT_OK(sd_future_group_add_many(group,
                                                          success_first ? success : error,
                                                          success_first ? error : success));

                        /* Settle both before dispatching either callback: success must win regardless
                         * of insertion or resolution order, even without IGNORE_ERRORS. */
                        if (resolve_success_first) {
                                ASSERT_OK(sd_future_resolve(success, 42));
                                ASSERT_OK(sd_future_resolve(error, -EIO));
                        } else {
                                ASSERT_OK(sd_future_resolve(error, -EIO));
                                ASSERT_OK(sd_future_resolve(success, 42));
                        }

                        ASSERT_OK(sd_event_loop(e));
                        ASSERT_EQ(sd_future_result(group), 42);
                        ASSERT_EQ(sd_future_result(success), 42);
                        ASSERT_ERROR(sd_future_result(error), EIO);
                }
}

/* WAIT_ANY|IGNORE_ERRORS (FIRST_SUCCESS): fast errorer, slower success, slowest pending;
 * group resolves with the success value; slowest is cancelled. */
TEST(future_group_first_success) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *fast_err = NULL, *medium_ok = NULL, *slow_ok = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY|SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &fast_err));
        ASSERT_OK(sd_future_new_defer(e, 77, &medium_ok));
        ASSERT_OK(sd_fiber_new(e, "slow-ok", suspend_fiber, NULL, NULL, &slow_ok));

        ASSERT_OK(sd_future_group_add(group, fast_err));
        ASSERT_OK(sd_future_group_add(group, medium_ok));
        ASSERT_OK(sd_future_group_add(group, slow_ok));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(group), 77);
        ASSERT_ERROR(sd_future_result(fast_err), EINVAL);
        ASSERT_EQ(sd_future_result(medium_ok), 77);
        ASSERT_ERROR(sd_future_result(slow_ok), ECANCELED);
}

/* WAIT_ANY|IGNORE_ERRORS, all fail: every child errors; group resolves with first error. */
TEST(future_group_first_success_all_fail) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *err_a = NULL, *err_b = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY|SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &err_a));
        ASSERT_OK(sd_future_new_defer(e, -EIO, &err_b));
        ASSERT_OK(sd_future_group_add(group, err_a));
        ASSERT_OK(sd_future_group_add(group, err_b));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), EINVAL);
        ASSERT_ERROR(sd_future_result(err_a), EINVAL);
        ASSERT_ERROR(sd_future_result(err_b), EIO);
}

/* External cancellation: long-running children + a deferred event source that cancels the
 * group; group and every child observe -ECANCELED. */
static int cancel_trigger(sd_event_source *src, void *userdata) {
        sd_future *group = ASSERT_PTR(userdata);
        return sd_future_cancel(group);
}

TEST(future_group_external_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *long_a = NULL, *long_b = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));

        ASSERT_OK(sd_fiber_new(e, "long-a", suspend_fiber, NULL, NULL, &long_a));
        ASSERT_OK(sd_fiber_new(e, "long-b", suspend_fiber, NULL, NULL, &long_b));
        ASSERT_OK(sd_future_group_add(group, long_a));
        ASSERT_OK(sd_future_group_add(group, long_b));

        /* Deferred event source runs after fibers have had a chance to suspend, then cancels
         * the group from outside the fiber stack. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *cancel_src = NULL;
        ASSERT_OK(sd_event_add_defer(e, &cancel_src, cancel_trigger, group));
        ASSERT_OK(sd_event_source_set_priority(cancel_src, 100));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), ECANCELED);
        ASSERT_ERROR(sd_future_result(long_a), ECANCELED);
        ASSERT_ERROR(sd_future_result(long_b), ECANCELED);
}

/* Drain invariant: a fail-fast group with a fast errorer + a still-sleeping sibling. The
 * group's done callback must see *every* child in RESOLVED state — the group may not
 * settle while any cancelled child is still draining. */
typedef struct DrainCheckState {
        sd_future *child_a;
        sd_future *child_b;
        int a_state_at_resolve;
        int b_state_at_resolve;
} DrainCheckState;

static int drain_check_cb(sd_future *f, void *userdata) {
        DrainCheckState *s = ASSERT_PTR(userdata);
        s->a_state_at_resolve = sd_future_state(s->child_a);
        s->b_state_at_resolve = sd_future_state(s->child_b);
        return 0;
}

TEST(future_group_resolves_after_children_drain) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL, *sleeper = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));

        /* The errorer yields once so the sleeper's dispatch fires first and the sleeper
         * actually enters its body before the errorer returns. That way the group's cancel
         * of the sleeper goes through the async (FIBER_STATE_SUSPENDED) path, not the
         * synchronous FIBER_STATE_INITIAL path — which is the case the drain invariant is
         * about. */
        int err_result = -EINVAL;
        ASSERT_OK(sd_fiber_new(e, "err", yield_then_return_fiber, &err_result, NULL, &errorer));
        ASSERT_OK(sd_fiber_new(e, "sleep", suspend_fiber, NULL, NULL, &sleeper));
        ASSERT_OK(sd_future_group_add(group, errorer));
        ASSERT_OK(sd_future_group_add(group, sleeper));

        DrainCheckState s = { .child_a = errorer, .child_b = sleeper };
        _cleanup_(sd_future_slot_unrefp) sd_future_slot *slot = NULL;
        ASSERT_OK(sd_future_add_callback(group, &slot, drain_check_cb, &s));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(s.a_state_at_resolve, (int) SD_FUTURE_RESOLVED);
        ASSERT_EQ(s.b_state_at_resolve, (int) SD_FUTURE_RESOLVED);
        ASSERT_ERROR(sd_future_result(group), EINVAL);
        ASSERT_ERROR(sd_future_result(sleeper), ECANCELED);
}

/* Parent cancellation: a fiber creates a group with one errorer, then suspends without ever
 * awaiting the group. When the errorer fails, the parent fiber's in-flight suspend must
 * return -ECANCELED. With IGNORE_ERRORS the parent is left alone (a wake-up callback on
 *     the group lifts the suspend so we don't hang). */
typedef struct ParentCancelState {
        uint64_t policy;
        int suspend_result;
        int group_result;
} ParentCancelState;

static int wake_parent_cb(sd_future *f, void *userdata) {
        return sd_fiber_resume(userdata, 0);
}

static int parent_cancel_driver(void *userdata) {
        ParentCancelState *s = ASSERT_PTR(userdata);
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL;

        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &group));
        if (s->policy)
                ASSERT_OK(sd_future_group_set_policy(group, s->policy));
        ASSERT_OK(sd_future_new_defer(sd_fiber_get_event(), -EINVAL, &errorer));
        ASSERT_OK(sd_future_group_add(group, errorer));

        /* Wake-up slot so we don't hang in the IGNORE_ERRORS case (where the parent isn't
         * cancelled). In the fail-fast case the queued -ECANCELED takes precedence over this
         * callback's normal resume value. */
        _cleanup_(sd_future_slot_unrefp) sd_future_slot *wake_slot = NULL;
        ASSERT_OK(sd_future_add_callback(group, &wake_slot, wake_parent_cb, sd_fiber_get_current()));

        s->suspend_result = sd_fiber_suspend();
        s->group_result = sd_future_result(group);
        return 0;
}

TEST(future_group_cancels_parent_on_child_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ParentCancelState s = {};
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "parent", parent_cancel_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(s.suspend_result, ECANCELED);
        ASSERT_ERROR(s.group_result, EINVAL);
}

/* Awaiting a group must return the child's error instead of cancelling the waiting parent. */
static int await_gets_error_driver(void *userdata) {
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL;
        int *await_result = ASSERT_PTR(userdata);

        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &group));
        ASSERT_OK(sd_future_new_defer(sd_fiber_get_event(), -EINVAL, &errorer));
        ASSERT_OK(sd_future_group_add(group, errorer));

        *await_result = sd_fiber_await(group);
        ASSERT_OK_ZERO(sd_fiber_yield());
        return 0;
}

TEST(future_group_await_returns_real_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        int await_result = 0;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(sd_fiber_new(e, "parent", await_gets_error_driver, &await_result, /* destroy= */ NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(driver));
        ASSERT_ERROR(await_result, EINVAL);
}

TEST(future_group_does_not_cancel_parent_with_ignore_errors) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ParentCancelState s = { .policy = SD_FUTURE_GROUP_IGNORE_ERRORS };
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "parent", parent_cancel_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        /* With IGNORE_ERRORS the parent isn't cancelled — the wake-up callback resumes the
         * suspend with 0, and we read the group's error via sd_future_result. */
        ASSERT_OK_ZERO(s.suspend_result);
        ASSERT_ERROR(s.group_result, EINVAL);
}

/* Add already-resolved child to a default group: group stays PENDING until the next event-loop
 * tick (via sd_future_add_callback's RESOLVED-on-fiber defer path), then resolves with the
 * child's result. */
typedef struct AddResolvedState {
        sd_future *child;
        sd_future *group;
        int add_result;
        int group_state_after_add;
        int await_result;
} AddResolvedState;

static int add_resolved_driver(void *userdata) {
        AddResolvedState *s = ASSERT_PTR(userdata);

        /* Drive the pre-built child to completion. The defer resolves with -EINVAL, which
         * makes sd_fiber_await return -EINVAL — we don't ASSERT_OK that. The child is now
         * RESOLVED and we can add it to the group. */
        (void) sd_fiber_await(s->child);
        ASSERT_EQ(sd_future_state(s->child), SD_FUTURE_RESOLVED);

        s->add_result = sd_future_group_add(s->group, s->child);
        s->group_state_after_add = sd_future_state(s->group);

        /* Await drives the loop one more tick so the defer that wraps the RESOLVED child can
         * fire group_child_resolved and settle the group. */
        s->await_result = sd_fiber_await(s->group);
        return 0;
}

TEST(future_group_add_resolved_child) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddResolvedState s = {};
        ASSERT_OK(sd_future_group_new(e, &s.group));
        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &s.child));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", add_resolved_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(s.add_result);
        ASSERT_EQ(s.group_state_after_add, SD_FUTURE_PENDING);
        ASSERT_ERROR(s.await_result, EINVAL);
        ASSERT_ERROR(sd_future_result(s.group), EINVAL);
        s.child = sd_future_unref(s.child);
        s.group = sd_future_unref(s.group);
}

/* add_many: convenience that adds multiple children in one call, behaves like add. */
typedef struct AddManyState {
        sd_future *a;
        sd_future *b;
        sd_future *c;
        sd_future *group;
        int join_result;
} AddManyState;

static int add_many_driver(void *userdata) {
        AddManyState *s = ASSERT_PTR(userdata);
        ASSERT_OK(sd_future_group_add_many(s->group, s->a, s->b, s->c));
        s->join_result = sd_fiber_await(s->group);
        return 0;
}

TEST(future_group_add_many) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddManyState s = {};
        ASSERT_OK(sd_future_group_new(e, &s.group));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.a));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.b));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.c));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", add_many_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(s.join_result);

        s.a = sd_future_unref(s.a);
        s.b = sd_future_unref(s.b);
        s.c = sd_future_unref(s.c);
        s.group = sd_future_unref(s.group);
}

/* Custom future ops whose cancel is a no-op on the first call and resolves on the second.
 * Used to drive a group into the "finalizing but draining" state synchronously: one cancel
 * of the group runs finalize, which calls our cancel once — but we don't resolve, so the
 * group's state stays PENDING with finalizing=true. */
typedef struct StubbornChild {
        unsigned cancels;
} StubbornChild;

static void* stubborn_child_alloc(void) {
        return new0(StubbornChild, 1);
}

static void stubborn_child_free(sd_future *f) {
        free(sd_future_get_private(f));
}

static int stubborn_child_cancel(sd_future *f) {
        StubbornChild *sc = ASSERT_PTR(sd_future_get_private(f));
        if (++sc->cancels >= 2)
                return sd_future_resolve(f, -ECANCELED);
        return 0;
}

static const sd_future_ops stubborn_child_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = stubborn_child_alloc,
        .free = stubborn_child_free,
        .cancel = stubborn_child_cancel,
};

static int failing_child_cancel(sd_future *f) {
        StubbornChild *sc = ASSERT_PTR(sd_future_get_private(f));

        sc->cancels++;
        return -EIO;
}

static const sd_future_ops cancel_failure_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = stubborn_child_alloc,
        .free = stubborn_child_free,
        .cancel = failing_child_cancel,
};

TEST(future_group_cancel_failure_still_drains) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *failing = NULL, *sibling = NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_new(e, &cancel_failure_ops, &failing));
        ASSERT_OK(sd_future_group_new(e, &sibling));
        ASSERT_OK(sd_future_group_add_many(group, failing, sibling));

        ASSERT_ERROR(sd_future_cancel(group), EIO);
        StubbornChild *sc = sd_future_get_private(failing);
        ASSERT_EQ(sc->cancels, 1U);
        ASSERT_EQ(sd_future_state(failing), SD_FUTURE_PENDING);
        ASSERT_ERROR(sd_future_result(sibling), ECANCELED);
        ASSERT_EQ(sd_future_group_size(group), 2U);

        /* The sibling's callback cannot finish the group while the failed cancellation is pending. */
        while (ASSERT_OK(sd_event_run(e, 0)) > 0)
                ;
        ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_resolve(failing, 42));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_ERROR(sd_future_result(group), ECANCELED);
        ASSERT_EQ(sd_future_result(failing), 42);
}

/* Cancelling a group with a still-draining child puts the group into the finalizing-but-PENDING
 * state. While in that state, sd_future_group_add() must reject with -ESTALE — a freshly-added
 * child would have missed the cancel loop and hang us forever waiting for it to settle. */
TEST(future_group_add_rejected_during_finalize) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *stubborn = NULL, *new_child = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_new(e, &stubborn_child_ops, &stubborn));
        ASSERT_OK(sd_future_group_add(group, stubborn));

        /* First cancel: triggers finalize, calls stubborn's cancel (no-op #1, child still
         * PENDING). Group is now finalizing=true with state PENDING. */
        ASSERT_OK(sd_future_cancel(group));
        ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);
        ASSERT_EQ(sd_future_state(stubborn), SD_FUTURE_PENDING);

        ASSERT_OK(sd_future_new_defer(e, 0, &new_child));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_add(group, new_child)), ESTALE);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_add_many(group, new_child)), ESTALE);
        ASSERT_EQ(sd_future_group_size(group), 1U);

        /* Second cancel of stubborn resolves it, which on the next loop iteration drives
         * group_child_resolved → future_group_check → group resolves with the locked-in
         * -ECANCELED. */
        ASSERT_OK(sd_future_cancel(stubborn));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), ECANCELED);
        ASSERT_ERROR(sd_future_result(stubborn), ECANCELED);
        ASSERT_OK_ZERO(sd_future_result(new_child));
}

/* Policy must be configured before any children are added: once a child is in flight, the
 * resolution mechanics are locked in. Multiple set_policy calls on a fresh group are fine. */
TEST(future_group_set_policy_rejected_after_add) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_cancel_unrefp) sd_future *group = NULL;
        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        ASSERT_OK(sd_future_group_new(e, &group));

        /* No children yet — set_policy can be called and re-called freely. */
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_set_policy(group, UINT64_C(1) << 8)), EINVAL);
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));
        ASSERT_OK(sd_future_group_set_policy(group,
                                             SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, 0, &child));
        ASSERT_OK(sd_future_group_add(group, child));

        /* Now that a child is registered, set_policy must reject. */
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ALL)), ESTALE);
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY)), ESTALE);
}

/* When the parent fiber itself drives the cancel of its own group, future_group_finalize() must
 * skip the parent-cancel path — fiber_cancel asserts against self-cancellation, and even if that
 * assertion were relaxed, queuing -ECANCELED on the parent would surface on a later suspend the
 * caller didn't expect. */
typedef struct SelfCancelState {
        int cancel_return;
        int group_result;
        int yield_result;
} SelfCancelState;

static int self_cancel_fiber(void *userdata) {
        SelfCancelState *s = ASSERT_PTR(userdata);
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *child = NULL;
        int r;

        r = sd_future_group_new(sd_fiber_get_event(), &group);
        if (r < 0)
                return r;

        r = sd_future_new_defer(sd_fiber_get_event(), 0, &child);
        if (r < 0)
                return r;

        r = sd_future_group_add(group, child);
        if (r < 0)
                return r;

        s->cancel_return = sd_future_cancel(group);
        s->group_result = sd_future_result(group);

        /* If the parent-cancel guard didn't work, -ECANCELED would be queued on us by
         * finalize() and surface here. Expect a clean yield (0). */
        s->yield_result = sd_fiber_yield();
        return 0;
}

TEST(future_group_does_not_cancel_parent_when_parent_drives_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        SelfCancelState s = {};
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "self-cancel", self_cancel_fiber, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(driver));
        ASSERT_OK(s.cancel_return);
        ASSERT_ERROR(s.group_result, ECANCELED);
        ASSERT_OK_ZERO(s.yield_result);
}

typedef struct ParentAwaitState {
        sd_future *group;
        sd_future *child;
        sd_future *parent;
        bool await;
        bool ready;
        int result;
} ParentAwaitState;

static int parent_await_driver(void *userdata) {
        ParentAwaitState *s = ASSERT_PTR(userdata);

        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &s->group));
        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &s->child));
        ASSERT_OK(sd_future_group_add(s->group, s->child));

        if (s->await)
                ASSERT_ERROR(sd_fiber_await(s->group), ECANCELED);
        else
                ASSERT_EQ(sd_fiber_suspend(), 42);

        s->ready = true;
        ASSERT_EQ(sd_fiber_suspend(), s->result);

        /* Parent cancellation does not replace the group's result. A later await of the resolved
         * group returns that result, just like sd_future_result(). */
        if (s->result == -ECANCELED) {
                ASSERT_EQ(sd_future_state(s->group), SD_FUTURE_RESOLVED);
                ASSERT_ERROR(sd_future_result(s->group), EIO);
                ASSERT_ERROR(sd_fiber_await(s->group), EIO);
        }
        return 0;
}

TEST(future_group_parent_await_scope) {
        bool await;

        FOREACH_ARGUMENT(await, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *parent = NULL;
                ParentAwaitState s = { .await = await, .result = -ECANCELED };

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_fiber_new(e, "parent-await", parent_await_driver, &s,
                                       /* destroy= */ NULL, &parent));
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                if (s.await)
                        ASSERT_OK(sd_future_cancel(parent));
                else {
                        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_fiber_await(s.group)), ESRCH);
                        ASSERT_OK(sd_fiber_resume(parent, 42));
                }
                while (!s.ready)
                        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

                ASSERT_OK(sd_future_resolve(s.child, -EIO));
                while (ASSERT_OK(sd_event_run(e, 0)) > 0)
                        ;

                /* No exit-on-idle: only the child failure may wake the parent. */
                ASSERT_EQ(sd_future_state(parent), SD_FUTURE_RESOLVED);
                ASSERT_OK_ZERO(sd_future_result(parent));
                ASSERT_ERROR(sd_future_result(s.group), EIO);
                sd_future_unref(s.group);
                sd_future_unref(s.child);
        }
}

static int cancel_group_from_peer(void *userdata) {
        ParentAwaitState *s = ASSERT_PTR(userdata);

        sd_future_cancel_unref(sd_future_ref(s->group));
        return sd_fiber_resume(s->parent, 42);
}

TEST(future_group_external_cancel_leaves_parent_running) {
        bool peer;

        FOREACH_ARGUMENT(peer, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *parent = NULL, *canceller = NULL;
                ParentAwaitState s = { .result = 42 };

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                ASSERT_OK(sd_fiber_new(e, "parent", parent_await_driver, &s,
                                       /* destroy= */ NULL, &parent));
                s.parent = parent;
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_OK(sd_fiber_resume(parent, 42));
                while (!s.ready)
                        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

                if (peer)
                        ASSERT_OK(sd_fiber_new(e, "cancel-group", cancel_group_from_peer, &s,
                                               /* destroy= */ NULL, &canceller));
                else
                        ASSERT_OK(cancel_group_from_peer(&s));

                ASSERT_OK(sd_event_loop(e));
                ASSERT_OK_ZERO(sd_future_result(parent));
                if (peer)
                        ASSERT_OK_ZERO(sd_future_result(canceller));
                ASSERT_ERROR(sd_future_result(s.group), ECANCELED);
                sd_future_unref(s.group);
                sd_future_unref(s.child);
        }
}

static int peer_await_driver(void *userdata) {
        return sd_fiber_await(userdata);
}

TEST(future_group_peer_await_does_not_suppress_parent_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *parent = NULL, *peer = NULL;
        ParentAwaitState s = { .result = -ECANCELED };

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_fiber_new(e, "parent", parent_await_driver, &s,
                               /* destroy= */ NULL, &parent));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK(sd_fiber_resume(parent, 42));
        while (!s.ready)
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        ASSERT_OK(sd_fiber_new(e, "peer-await", peer_await_driver, s.group,
                               /* destroy= */ NULL, &peer));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK(sd_future_resolve(s.child, -EIO));
        while (ASSERT_OK(sd_event_run(e, 0)) > 0)
                ;

        ASSERT_EQ(sd_future_state(parent), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(parent));
        ASSERT_ERROR(sd_future_result(peer), EIO);
        sd_future_unref(s.group);
        sd_future_unref(s.child);
}

TEST(future_group_priority) {
        bool before_add;

        FOREACH_ARGUMENT(before_add, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL, *pending = NULL, *resolved = NULL,
                        *unsupported = NULL, *probe = NULL;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_group_new(e, &resolved));
                ASSERT_OK(sd_future_resolve(resolved, 0));
                ASSERT_OK(sd_future_new(e, &stubborn_child_ops, &unsupported));
                ASSERT_OK(sd_future_new_defer(e, 0, &probe));
                ASSERT_OK(sd_future_new_defer(e, 0, &pending));
                if (before_add)
                        ASSERT_OK(sd_future_set_priority(group, -10));
                ASSERT_OK(ASSERT_RETURN_EXPECTED(sd_future_group_add_many(group, resolved, unsupported, pending)));
                if (!before_add)
                        ASSERT_OK(ASSERT_RETURN_EXPECTED(sd_future_set_priority(group, -10)));

                /* The pending child overtakes a source created earlier at normal priority. Resolved children
                 * and children without priority support must not make either operation fail. */
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_state(pending), SD_FUTURE_RESOLVED);
                ASSERT_EQ(sd_future_state(probe), SD_FUTURE_PENDING);
                ASSERT_OK(sd_future_resolve(unsupported, 0));
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                ASSERT_OK(sd_event_loop(e));
                ASSERT_OK_ZERO(sd_future_result(group));
                ASSERT_OK_ZERO(sd_future_result(probe));
        }
}

TEST(future_group_priority_unset) {
        bool explicit_priority;

        FOREACH_ARGUMENT(explicit_priority, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL, *pending = NULL, *probe = NULL;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_new_defer(e, 0, &pending));
                ASSERT_OK(sd_future_set_priority(pending, -10));
                ASSERT_OK(sd_future_new_defer(e, 0, &probe));
                ASSERT_OK(sd_future_set_priority(probe, -5));
                if (explicit_priority)
                        ASSERT_OK(sd_future_set_priority(group, 0));
                ASSERT_OK(sd_future_group_add(group, pending));

                /* An unset group priority preserves the child's priority; explicitly setting zero
                 * overrides it, making the probe run first. */
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_state(pending), explicit_priority ? SD_FUTURE_PENDING : SD_FUTURE_RESOLVED);
                ASSERT_EQ(sd_future_state(probe), explicit_priority ? SD_FUTURE_RESOLVED : SD_FUTURE_PENDING);
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                ASSERT_OK(sd_event_loop(e));
                ASSERT_OK_ZERO(sd_future_result(group));
                ASSERT_OK_ZERO(sd_future_result(probe));
        }
}

static int child_set_priority_fail(sd_future *f, int64_t priority) {
        return -EIO;
}

static const sd_future_ops priority_failure_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = stubborn_child_alloc,
        .free = stubborn_child_free,
        .cancel = stubborn_child_cancel,
        .set_priority = child_set_priority_fail,
};

TEST(future_group_priority_add_failure) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_cancel_unrefp) sd_future *group = NULL;
        _cleanup_(sd_future_unrefp) sd_future *child = NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_set_priority(group, -10));
        ASSERT_OK(sd_future_new(e, &priority_failure_ops, &child));
        ASSERT_ERROR(sd_future_group_add(group, child), EIO);
        ASSERT_EQ(sd_future_group_size(group), 0U);

        /* A failed add must leave neither membership nor a callback behind. */
        ASSERT_OK(sd_future_resolve(child, 0));
        ASSERT_OK_ZERO(sd_event_run(e, 0));
        ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);
}

TEST(future_group_priority_failure) {
        bool failing_first;

        FOREACH_ARGUMENT(failing_first, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL, *accepting = NULL, *failing = NULL,
                        *later = NULL, *probe = NULL;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_new(e, &priority_failure_ops, &failing));
                ASSERT_OK(sd_future_new_defer(e, 0, &probe));
                ASSERT_OK(sd_future_set_priority(probe, -5));
                ASSERT_OK(sd_future_new_defer(e, 0, &accepting));
                ASSERT_OK(sd_future_group_add_many(group,
                                                  failing_first ? failing : accepting,
                                                  failing_first ? accepting : failing));
                ASSERT_ERROR(sd_future_set_priority(group, -10), EIO);

                /* A failure neither stops updates to the other children nor installs the attempted
                 * priority as the group's default for later additions. */
                ASSERT_OK(sd_future_new_defer(e, 0, &later));
                ASSERT_OK(sd_future_group_add(group, later));
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_state(accepting), SD_FUTURE_RESOLVED);
                ASSERT_EQ(sd_future_state(probe), SD_FUTURE_PENDING);
                ASSERT_EQ(sd_future_state(later), SD_FUTURE_PENDING);
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_state(probe), SD_FUTURE_RESOLVED);
                ASSERT_EQ(sd_future_state(later), SD_FUTURE_PENDING);

                ASSERT_OK(sd_future_resolve(failing, 0));
                ASSERT_OK(sd_event_set_exit_on_idle(e, true));
                ASSERT_OK(sd_event_loop(e));
                ASSERT_OK_ZERO(sd_future_result(group));
                ASSERT_OK_ZERO(sd_future_result(later));
        }
}

TEST(future_group_add_many_rollback) {
        bool existing;

        FOREACH_ARGUMENT(existing, false, true) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                _cleanup_(sd_future_unrefp) sd_future *group = NULL, *original = NULL,
                        *first = NULL, *second = NULL, *failing = NULL;

                ASSERT_OK(sd_event_new(&e));
                ASSERT_OK(sd_future_group_new(e, &group));
                ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));
                ASSERT_OK(sd_future_set_priority(group, -10));
                if (existing) {
                        ASSERT_OK(sd_future_group_new(e, &original));
                        ASSERT_OK(sd_future_group_add(group, original));
                }
                ASSERT_OK(sd_future_new_defer(e, 0, &first));
                ASSERT_OK(sd_future_new_defer(e, 0, &second));
                ASSERT_OK(sd_future_new(e, &priority_failure_ops, &failing));

                ASSERT_ERROR(sd_future_group_add_many(group, first, second, failing), EIO);
                ASSERT_EQ(sd_future_group_size(group), (size_t) existing);
                ASSERT_OK(sd_future_resolve(failing, -EIO));

                /* Only the two defer futures may dispatch: every partially registered callback must
                 * be removed, and any pre-existing membership must survive the rollback. */
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_OK_ZERO(sd_event_run(e, 0));
                ASSERT_OK_ZERO(sd_future_result(first));
                ASSERT_OK_ZERO(sd_future_result(second));
                ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);

                if (existing)
                        ASSERT_OK(sd_future_resolve(original, 42));
                else
                        ASSERT_OK(ASSERT_RETURN_EXPECTED(sd_future_group_add(group, first)));
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));
                ASSERT_EQ(sd_future_result(group), existing ? 42 : 0);
        }
}

TEST(future_group_rejects_cross_event_child) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL, *other = NULL;
        _cleanup_(sd_future_cancel_unrefp) sd_future *group = NULL;
        _cleanup_(sd_future_unrefp) sd_future *child = NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_new(&other));
        ASSERT_OK(sd_future_group_new(e, &group));
        ASSERT_OK(sd_future_group_new(other, &child));

        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_add(group, child)), EINVAL);
        ASSERT_OK(sd_future_resolve(child, -EIO));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(sd_future_group_add(group, child)), EINVAL);
        ASSERT_EQ(sd_future_group_size(group), 0U);
        ASSERT_OK_ZERO(sd_event_run(e, 0));
        ASSERT_OK_ZERO(sd_event_run(other, 0));
        ASSERT_EQ(sd_future_state(group), SD_FUTURE_PENDING);
}

typedef struct CrossEventParentState {
        sd_event *event;
        sd_future *group;
} CrossEventParentState;

static int cross_event_parent_driver(void *userdata) {
        CrossEventParentState *s = ASSERT_PTR(userdata);

        ASSERT_OK(sd_future_group_new(s->event, &s->group));
        ASSERT_EQ(sd_fiber_suspend(), 42);
        return 0;
}

TEST(future_group_does_not_capture_cross_event_parent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL, *other = NULL;
        _cleanup_(sd_future_unrefp) sd_future *parent = NULL, *child = NULL;
        CrossEventParentState s = {};

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_new(&other));
        s.event = other;
        ASSERT_OK(sd_future_group_new(other, &child));
        ASSERT_OK(sd_fiber_new(e, "cross-event-parent", cross_event_parent_driver, &s,
                               /* destroy= */ NULL, &parent));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK(sd_future_group_add(s.group, child));
        ASSERT_OK(sd_future_resolve(child, -EIO));
        while (ASSERT_OK(sd_event_run(other, 0)) > 0)
                ;
        ASSERT_ERROR(sd_future_result(s.group), EIO);

        /* A failure on the other loop must neither schedule nor cancel the creating fiber. */
        ASSERT_OK_ZERO(sd_event_run(e, 0));
        ASSERT_EQ(sd_future_state(parent), SD_FUTURE_PENDING);
        ASSERT_OK(sd_fiber_resume(parent, 42));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_ZERO(sd_future_result(parent));
        sd_future_unref(s.group);
}

typedef struct ParentLifetimeState {
        sd_future *group;
        sd_future *child;
        bool parent_freed;
} ParentLifetimeState;

static int parent_returns_before_child(void *userdata) {
        ParentLifetimeState *s = ASSERT_PTR(userdata);

        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &s->group));
        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &s->child));
        ASSERT_OK(sd_future_group_add(s->group, s->child));
        return 0;
}

static void parent_lifetime_destroy(void *userdata) {
        ParentLifetimeState *s = ASSERT_PTR(userdata);

        s->parent_freed = true;
}

TEST(future_group_outlives_parent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *parent = NULL;
        ParentLifetimeState s = {};

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_fiber_new(e, "short-lived-parent", parent_returns_before_child, &s,
                               parent_lifetime_destroy, &parent));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_ZERO(sd_future_result(parent));
        parent = sd_future_unref(parent);

        /* Dispatch the parent-resolution callbacks before the child fails. They must release their
         * references and forget the parent, since a later child error must not cancel freed memory. */
        while (ASSERT_OK(sd_event_run(e, 0)) > 0)
                ;
        ASSERT_TRUE(s.parent_freed);
        ASSERT_EQ(sd_future_state(s.group), SD_FUTURE_PENDING);
        ASSERT_OK(sd_future_resolve(s.child, -EIO));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_ERROR(sd_future_result(s.group), EIO);
        sd_future_unref(s.group);
        sd_future_unref(s.child);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
