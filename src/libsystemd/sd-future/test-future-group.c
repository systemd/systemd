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
        ASSERT_OK(sd_future_group_new(e, &group));
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
        ASSERT_OK(sd_future_group_new(e, &group));
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

        ASSERT_OK(sd_future_group_new(sd_fiber_get_event(), &group));
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
        ASSERT_ERROR(sd_future_group_add(group, new_child), ESTALE);

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
        ASSERT_OK(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY));
        ASSERT_OK(sd_future_group_set_policy(group,
                                             SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS));

        ASSERT_OK(sd_future_new_defer(e, 0, &child));
        ASSERT_OK(sd_future_group_add(group, child));

        /* Now that a child is registered, set_policy must reject. */
        ASSERT_ERROR(sd_future_group_set_policy(group, 0), ESTALE);
        ASSERT_ERROR(sd_future_group_set_policy(group, SD_FUTURE_GROUP_WAIT_ANY), ESTALE);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
