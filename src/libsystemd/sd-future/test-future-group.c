/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

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

/* WAIT_ALL happy path: three children all succeed. */
TEST(future_group_wait_all_happy) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *c1 = NULL, *c2 = NULL, *c3 = NULL;
        ASSERT_OK(sd_future_group_new(&group));
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
        ASSERT_OK(sd_future_group_new(&group));

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
        ASSERT_OK(sd_future_group_new(&group));
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
        ASSERT_OK(sd_future_group_new(&group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));

        ASSERT_OK(sd_future_new_defer(e, 0, &fast));
        ASSERT_OK(sd_fiber_new(e, "medium", suspend_fiber, NULL, NULL, &medium));
        ASSERT_OK(sd_fiber_new(e, "slow", suspend_fiber, NULL, NULL, &slow));
        ASSERT_OK(sd_future_group_add(group, fast));
        ASSERT_OK(sd_future_group_add(group, medium));
        ASSERT_OK(sd_future_group_add(group, slow));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(group));
        ASSERT_OK_ZERO(sd_future_result(fast));
        ASSERT_ERROR(sd_future_result(medium), ECANCELED);
        ASSERT_ERROR(sd_future_result(slow), ECANCELED);
}

/* WAIT_ANY|IGNORE_ERRORS (FIRST_SUCCESS): fast errorer, slower success, slowest pending;
 * group resolves with the success value; slowest is cancelled. */
TEST(future_group_first_success) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *fast_err = NULL, *medium_ok = NULL, *slow_ok = NULL;
        ASSERT_OK(sd_future_group_new(&group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY|SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &fast_err));
        ASSERT_OK(sd_future_new_defer(e, 0, &medium_ok));
        ASSERT_OK(sd_fiber_new(e, "slow-ok", suspend_fiber, NULL, NULL, &slow_ok));

        ASSERT_OK(sd_future_group_add(group, fast_err));
        ASSERT_OK(sd_future_group_add(group, medium_ok));
        ASSERT_OK(sd_future_group_add(group, slow_ok));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(group));
        ASSERT_ERROR(sd_future_result(fast_err), EINVAL);
        ASSERT_OK_ZERO(sd_future_result(medium_ok));
        ASSERT_ERROR(sd_future_result(slow_ok), ECANCELED);
}

/* WAIT_ANY|IGNORE_ERRORS, all fail: every child errors; group resolves with first error. */
TEST(future_group_first_success_all_fail) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *err_a = NULL, *err_b = NULL;
        ASSERT_OK(sd_future_group_new(&group));
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY|SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &err_a));
        ASSERT_OK(sd_future_new_defer(e, -EINVAL, &err_b));
        ASSERT_OK(sd_future_group_add(group, err_a));
        ASSERT_OK(sd_future_group_add(group, err_b));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(group), EINVAL);
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
        ASSERT_OK(sd_future_group_new(&group));

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
        ASSERT_OK(sd_future_group_new(&group));

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

        ASSERT_OK(sd_future_group_new(&group));
        if (s->policy)
                ASSERT_OK(sd_future_group_set_policy(group, s->policy));
        ASSERT_OK(sd_future_new_defer(sd_fiber_get_event(), -EINVAL, &errorer));
        ASSERT_OK(sd_future_group_add(group, errorer));

        /* Wake-up slot so we don't hang in the IGNORE_ERRORS case (where the parent isn't
         * cancelled). In the fail-fast case the parent's state goes CANCELLED before this
         * fires, and sd_fiber_resume on a non-SUSPENDED fiber is a no-op. */
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

/* sd_future_group_await() suppresses parent-cancel: when the awaiter has explicitly
 * opted in to receiving the group's resolution, the await returns the group's actual
 * error (here -EINVAL) instead of -ECANCELED from the parent-cancel path. */
typedef struct AwaitGetsErrorState {
        int await_result;
} AwaitGetsErrorState;

static int await_gets_error_driver(void *userdata) {
        AwaitGetsErrorState *s = ASSERT_PTR(userdata);
        _cleanup_(sd_future_unrefp) sd_future *group = NULL, *errorer = NULL;

        ASSERT_OK(sd_future_group_new(&group));
        ASSERT_OK(sd_future_new_defer(sd_fiber_get_event(), -EINVAL, &errorer));
        ASSERT_OK(sd_future_group_add(group, errorer));

        s->await_result = sd_future_group_await(group);
        return 0;
}

TEST(future_group_await_returns_real_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AwaitGetsErrorState s = {};
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "parent", await_gets_error_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(s.await_result, EINVAL);
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
        s->await_result = sd_future_group_await(s->group);
        return 0;
}

TEST(future_group_add_resolved_child) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddResolvedState s = {};
        ASSERT_OK(sd_future_group_new(&s.group));
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

/* add_many with NULL sentinel: convenience adds multiple children, behaves like add. */
typedef struct AddManyState {
        sd_future *a;
        sd_future *b;
        sd_future *c;
        sd_future *group;
        int join_result;
} AddManyState;

static int add_many_driver(void *userdata) {
        AddManyState *s = ASSERT_PTR(userdata);
        ASSERT_OK(sd_future_group_add_many(s->group, s->a, s->b, s->c, NULL));
        s->join_result = sd_future_group_await(s->group);
        return 0;
}

TEST(future_group_add_many) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddManyState s = {};
        ASSERT_OK(sd_future_group_new(&s.group));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.a));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.b));
        ASSERT_OK(sd_future_new_defer(e, 0, &s.c));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", add_many_driver, &s, NULL, &driver));
        /* Driver must run before the children resolve — otherwise WAIT_ALL would resolve on
         * the first add (since all already-resolved children are immediately "all done"). */
        ASSERT_OK(sd_future_set_priority(driver, -1));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(s.join_result);

        s.a = sd_future_unref(s.a);
        s.b = sd_future_unref(s.b);
        s.c = sd_future_unref(s.c);
        s.group = sd_future_unref(s.group);
}

/* Slot lifecycle: two callbacks on the same future, both fire with their userdata;
 * dropping a slot before resolution prevents that callback from firing. */
static int counting_callback(sd_future *f, void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        (*counter)++;
        return 0;
}

typedef struct SlotLifecycleState {
        sd_future *target;
        int a_count;
        int b_count;
        int c_count;
        sd_future_slot *slot_a;
        sd_future_slot *slot_b;
        sd_future_slot *slot_c;
} SlotLifecycleState;

TEST(future_group_slot_lifecycle) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        SlotLifecycleState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        /* a and b stay alive past resolution; c is dropped before resolution. */
        ASSERT_OK(sd_future_add_callback(s.target, &s.slot_a, counting_callback, &s.a_count));
        ASSERT_OK(sd_future_add_callback(s.target, &s.slot_b, counting_callback, &s.b_count));
        ASSERT_OK(sd_future_add_callback(s.target, &s.slot_c, counting_callback, &s.c_count));
        s.slot_c = sd_future_slot_unref(s.slot_c);

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(s.a_count, 1);
        ASSERT_EQ(s.b_count, 1);
        ASSERT_EQ(s.c_count, 0); /* c was dropped before resolve, never fired. */

        /* Slots a and b are still alive (we hold refs); cleanly drop them now. */
        s.slot_a = sd_future_slot_unref(s.slot_a);
        s.slot_b = sd_future_slot_unref(s.slot_b);
        s.target = sd_future_unref(s.target);
}

typedef struct FloatingState {
        int call_count;
        int last_result;
} FloatingState;

static int floating_callback(sd_future *f, void *userdata) {
        FloatingState *s = ASSERT_PTR(userdata);
        s->call_count++;
        s->last_result = sd_future_result(f);
        return 0;
}

/* Floating slot fires normally on resolve and is cleaned up afterwards. */
TEST(future_group_floating_slot_fires_on_resolve) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        FloatingState fs = {};
        _cleanup_(sd_future_unrefp) sd_future *target = NULL;
        ASSERT_OK(sd_future_new_defer(e, 0, &target));
        ASSERT_OK(sd_future_add_callback(target, /*ret_slot=*/NULL, floating_callback, &fs));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(fs.call_count, 1);
        ASSERT_OK_ZERO(fs.last_result);
}

/* Bare sd_future_new_defer: a defer resolves with result 0 on the next event-loop tick.
 * Callbacks are added separately via sd_future_add_callback; here we exercise both: the
 * bare await + a registered callback that observes the defer at fire time. */
typedef struct DeferBasicState {
        sd_future *defer;
        sd_future_slot *slot;
        int cb_fired_count;
        int cb_first_arg_matches;
        int await_result;
} DeferBasicState;

static int defer_basic_cb(sd_future *f, void *userdata) {
        DeferBasicState *s = ASSERT_PTR(userdata);
        s->cb_fired_count++;
        s->cb_first_arg_matches = (f == s->defer) ? 1 : -1;
        return 0;
}

static int defer_basic_driver(void *userdata) {
        DeferBasicState *s = ASSERT_PTR(userdata);
        ASSERT_OK(sd_future_new_defer(sd_fiber_get_event(), 0, &s->defer));
        ASSERT_OK(sd_future_add_callback(s->defer, &s->slot, defer_basic_cb, s));
        s->await_result = sd_fiber_await(s->defer);
        return 0;
}

TEST(future_new_defer_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        DeferBasicState s = {};
        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", defer_basic_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(s.cb_fired_count, 1);
        ASSERT_EQ(s.cb_first_arg_matches, 1);
        ASSERT_OK_ZERO(s.await_result);
        s.slot = sd_future_slot_unref(s.slot);
        s.defer = sd_future_unref(s.defer);
}

/* sd_future_add_callback on a RESOLVED future from inside a fiber defers the callback
 * by one tick (matches Python's add_done_callback semantics). The callback's first arg
 * is the original (already RESOLVED) future, not the internal defer. */
typedef struct AddCallbackResolvedFiberState {
        sd_future *target;
        sd_future_slot *slot;
        int fired_first_arg_matches;
        int fired_count;
        bool fired_before_yield;
} AddCallbackResolvedFiberState;

static int add_cb_resolved_fiber_cb(sd_future *f, void *userdata) {
        AddCallbackResolvedFiberState *s = ASSERT_PTR(userdata);
        s->fired_first_arg_matches = (f == s->target) ? 1 : -1;
        s->fired_count++;
        return 0;
}

static int add_cb_resolved_fiber_driver(void *userdata) {
        AddCallbackResolvedFiberState *s = ASSERT_PTR(userdata);

        /* Drive target to RESOLVED first. */
        (void) sd_fiber_await(s->target);
        ASSERT_EQ(sd_future_state(s->target), SD_FUTURE_RESOLVED);

        ASSERT_OK(sd_future_add_callback(s->target, &s->slot, add_cb_resolved_fiber_cb, s));

        /* The callback must not have fired yet — it's scheduled for the next tick. */
        s->fired_before_yield = (s->fired_count > 0);

        /* Yield via a zero-length sleep so the defer can run, then verify the callback fired. */
        ASSERT_OK(sd_fiber_yield());
        return 0;
}

TEST(add_callback_resolved_in_fiber_defers) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddCallbackResolvedFiberState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", add_cb_resolved_fiber_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_FALSE(s.fired_before_yield);
        ASSERT_EQ(s.fired_count, 1);
        ASSERT_EQ(s.fired_first_arg_matches, 1);
        s.slot = sd_future_slot_unref(s.slot);
        s.target = sd_future_unref(s.target);
}

/* sd_future_add_callback on a RESOLVED future outside any fiber runs the callback inline,
 *     before the function returns — there's no event loop to defer onto. */
typedef struct AddCallbackResolvedInlineState {
        int fired_count;
        sd_future *target;
        int fired_first_arg_matches;
} AddCallbackResolvedInlineState;

static int add_cb_resolved_inline_cb(sd_future *f, void *userdata) {
        AddCallbackResolvedInlineState *s = ASSERT_PTR(userdata);
        s->fired_count++;
        s->fired_first_arg_matches = (f == s->target) ? 1 : -1;
        return 0;
}

TEST(add_callback_resolved_no_fiber_runs_inline) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddCallbackResolvedInlineState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        /* Run the event loop so the target fiber completes. */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_state(s.target), SD_FUTURE_RESOLVED);

        /* We're now outside any fiber — sd_fiber_is_running() is false. The callback must
         * fire inline before add_callback returns. */
        _cleanup_(sd_future_slot_unrefp) sd_future_slot *slot = NULL;
        ASSERT_EQ(s.fired_count, 0);
        ASSERT_OK(sd_future_add_callback(s.target, &slot, add_cb_resolved_inline_cb, &s));
        ASSERT_EQ(s.fired_count, 1);
        ASSERT_EQ(s.fired_first_arg_matches, 1);

        s.target = sd_future_unref(s.target);
}

/* Floating variant of add_callback_resolved_in_fiber_defers: ret_slot==NULL means the
 * future owns the slot. The defer must still fire on the next tick, just like the
 * non-floating case. */
typedef struct ResolvedFiberFloatingState {
        sd_future *target;
        int fired_count;
        int fired_first_arg_matches;
} ResolvedFiberFloatingState;

static int resolved_fiber_floating_cb(sd_future *f, void *userdata) {
        ResolvedFiberFloatingState *s = ASSERT_PTR(userdata);
        s->fired_count++;
        s->fired_first_arg_matches = (f == s->target) ? 1 : -1;
        return 0;
}

static int resolved_fiber_floating_fires_driver(void *userdata) {
        ResolvedFiberFloatingState *s = ASSERT_PTR(userdata);

        (void) sd_fiber_await(s->target);
        ASSERT_EQ(sd_future_state(s->target), SD_FUTURE_RESOLVED);

        ASSERT_OK(sd_future_add_callback(s->target, /*ret_slot=*/NULL, resolved_fiber_floating_cb, s));

        ASSERT_OK(sd_fiber_yield());
        return 0;
}

TEST(add_callback_resolved_in_fiber_floating_fires) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ResolvedFiberFloatingState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", resolved_fiber_floating_fires_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(s.fired_count, 1);
        ASSERT_EQ(s.fired_first_arg_matches, 1);
        s.target = sd_future_unref(s.target);
}

/* Floating slot on a RESOLVED future from inside a fiber, then the only ref to
 * the future is dropped before the defer tick. The floating slot must be tracked in
 * f->slots so sd_future_free can disable its defer source — otherwise the source would
 * fire with a stale userdata pointing to freed memory. */
static int resolved_fiber_floating_freed_driver(void *userdata) {
        ResolvedFiberFloatingState *s = ASSERT_PTR(userdata);

        (void) sd_fiber_await(s->target);
        ASSERT_EQ(sd_future_state(s->target), SD_FUTURE_RESOLVED);

        ASSERT_OK(sd_future_add_callback(s->target, /*ret_slot=*/NULL, resolved_fiber_floating_cb, s));

        /* Drop the only remaining external ref before the defer tick. The future owns the
         * floating slot; freeing the future must tear the slot down (and disable the defer)
         * rather than leaving it dangling. */
        s->target = sd_future_unref(s->target);

        ASSERT_OK(sd_fiber_yield());
        return 0;
}

TEST(add_callback_resolved_in_fiber_floating_future_freed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ResolvedFiberFloatingState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", resolved_fiber_floating_freed_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(s.fired_count, 0);
}

/* Floating callback on a RESOLVED future outside any fiber: runs inline, no slot to manage. */
TEST(add_callback_resolved_no_fiber_floating_runs_inline) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        AddCallbackResolvedInlineState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_state(s.target), SD_FUTURE_RESOLVED);

        ASSERT_EQ(s.fired_count, 0);
        ASSERT_OK(sd_future_add_callback(s.target, /*ret_slot=*/NULL, add_cb_resolved_inline_cb, &s));
        ASSERT_EQ(s.fired_count, 1);
        ASSERT_EQ(s.fired_first_arg_matches, 1);

        s.target = sd_future_unref(s.target);
}

/* Dropping the wrapping slot before the defer tick fires must prevent the callback from
 * ever running. The defer's source gets disabled in defer_future_free (cancel-on-free
 * path), so the source won't fire with a dangling userdata. */
typedef struct DeferCancelState {
        sd_future *target;
        int fired_count;
} DeferCancelState;

static int defer_cancel_cb(sd_future *f, void *userdata) {
        DeferCancelState *s = ASSERT_PTR(userdata);
        s->fired_count++;
        return 0;
}

static int defer_cancel_driver(void *userdata) {
        DeferCancelState *s = ASSERT_PTR(userdata);

        (void) sd_fiber_await(s->target);
        ASSERT_EQ(sd_future_state(s->target), SD_FUTURE_RESOLVED);

        sd_future_slot *slot = NULL;
        ASSERT_OK(sd_future_add_callback(s->target, &slot, defer_cancel_cb, s));

        /* Drop the slot before the defer fires — the wrapping slot owns the defer; dropping
         * it unrefs the defer, disabling the underlying source. */
        sd_future_slot_unref(slot);

        /* Yield. If the source weren't disabled, defer_handler would fire here and the
         * callback would run. */
        ASSERT_OK(sd_fiber_yield());
        return 0;
}

TEST(defer_slot_cancel_before_fire) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        DeferCancelState s = {};
        ASSERT_OK(sd_future_new_defer(e, 0, &s.target));

        _cleanup_(sd_future_unrefp) sd_future *driver = NULL;
        ASSERT_OK(sd_fiber_new(e, "driver", defer_cancel_driver, &s, NULL, &driver));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(s.fired_count, 0);
        s.target = sd_future_unref(s.target);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
