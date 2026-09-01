/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>

#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "macro.h"

typedef struct FutureGroup {
        uint64_t policy;

        sd_future_slot **slots;
        size_t n_slots;

        /* The fiber the group was created on (captured at sd_future_group_new()). When the
         * group settles on an error and IGNORE_ERRORS is unset, this fiber is cancelled so it
         * notices the failure even if it hasn't started awaiting the group (a child error cancels
         * the parent). parent_slot's callback NULLs `parent` if the parent resolves before the
         * group does.
         *
         * parent_awaiting is set by sd_future_group_await(): it signals that someone is
         * already going to observe the group's resolution via the await path, so cancelling
         * the parent would just replace the group's real error with -ECANCELED. */
        sd_future *parent;
        sd_future_slot *parent_slot;
        bool parent_awaiting;

        /* Set once future_group_finalize() has been entered. The outcome is decided (stored in
         * `result`) and the group is "draining" — waiting for any still-pending children to
         * actually settle before we resolve. While set, the result cannot change and add
         * rejects with -ESTALE. */
        bool finalizing;
        int result;

        /* Reentrancy guard: set while finalize() is iterating slots so that cascading
         * child_resolved callbacks (from synchronous cancellations) don't re-run
         * future_group_check() and re-scan the slot vector mid-loop. */
        bool resolving;
} FutureGroup;

static void* future_group_alloc(void) {
        return new0(FutureGroup, 1);
}

static void future_group_free(sd_future *f) {
        FutureGroup *fg = ASSERT_PTR(sd_future_get_private(f));

        sd_future_slot_unref(fg->parent_slot);
        FOREACH_ARRAY(slot_p, fg->slots, fg->n_slots)
                sd_future_slot_unref(*slot_p);
        free(fg->slots);
        free(fg);
}

static int future_group_parent_resolved(sd_future *parent, void *userdata) {
        FutureGroup *fg = ASSERT_PTR(userdata);
        fg->parent = NULL;
        return 0;
}

static int future_group_check(sd_future *g);

static int future_group_finalize(sd_future *g, int result) {
        FutureGroup *fg = ASSERT_PTR(sd_future_get_private(g));
        int r = 0;

        if (fg->finalizing)
                /* Outcome already locked: ignore subsequent attempts. Mirrors the old "group
                 * is already RESOLVED, so further cancels are no-ops" behaviour. */
                return 0;

        fg->finalizing = true;
        fg->result = result;

        fg->resolving = true;
        FOREACH_ARRAY(slot, fg->slots, fg->n_slots) {
                sd_future *child = sd_future_slot_get_future(*slot);
                if (sd_future_state(child) == SD_FUTURE_PENDING)
                        RET_GATHER(r, sd_future_cancel(child));
        }
        fg->resolving = false;

        /* If we're settling because of an error (and the user hasn't opted into ignoring
         * errors), cancel the parent fiber so it notices the failure even if it hasn't
         * started awaiting the group yet. Skip when parent is the currently-running fiber
         * (e.g. the parent itself just called sd_future_cancel(group)): fiber_cancel asserts
         * against self-cancellation. */
        if (result < 0 &&
            !(fg->policy & SD_FUTURE_GROUP_IGNORE_ERRORS) &&
            !fg->parent_awaiting &&
            fg->parent &&
            fg->parent != sd_fiber_get_current())
                RET_GATHER(r, sd_future_cancel(fg->parent));

        /* Re-check: if every child settled synchronously during the cancel loop the group can
         * resolve now; otherwise wait for the group_child_resolved callbacks to drive the
         * drain branch of check(). */
        RET_GATHER(r, future_group_check(g));
        return r;
}

static int future_group_check(sd_future *g) {
        FutureGroup *fg = ASSERT_PTR(sd_future_get_private(g));

        if (sd_future_state(g) == SD_FUTURE_RESOLVED)
                return 0;
        if (fg->resolving)
                return 0;

        if (fg->finalizing) {
                /* Outcome decided; resolve once every child has actually settled so callers
                 * observing the group's resolution see every child in RESOLVED state. An empty
                 * finalizing group resolves immediately (the FOREACH_ARRAY body never runs). */
                FOREACH_ARRAY(slot, fg->slots, fg->n_slots)
                        if (sd_future_state(sd_future_slot_get_future(*slot)) != SD_FUTURE_RESOLVED)
                                return 0;
                return sd_future_resolve(g, fg->result);
        }

        if (fg->n_slots == 0)
                /* Empty group has nothing to wait for: leave it pending so the user can still
                 * add children (or cancel the group). Otherwise an early set_policy on a
                 * fresh group would settle it before any child got added. */
                return 0;

        bool wait_any = fg->policy & SD_FUTURE_GROUP_WAIT_ANY;
        bool ignore_errors = fg->policy & SD_FUTURE_GROUP_IGNORE_ERRORS;

        size_t n_resolved = 0;
        int first_error = 0, first_success = 0;
        bool any_success = false;

        FOREACH_ARRAY(slot_p, fg->slots, fg->n_slots) {
                sd_future *child = sd_future_slot_get_future(*slot_p);
                if (sd_future_state(child) != SD_FUTURE_RESOLVED)
                        continue;

                n_resolved++;
                int cr = sd_future_result(child);
                if (cr < 0) {
                        if (first_error == 0)
                                first_error = cr;
                } else if (!any_success) {
                        any_success = true;
                        first_success = cr;
                }
        }

        bool all_done = (n_resolved == fg->n_slots);

        int result;
        if (wait_any && any_success)
                result = first_success;        /* wait_any short-circuits on first success */
        else if (!ignore_errors && first_error != 0)
                result = first_error;          /* fail-fast on error unless ignored */
        else if (all_done)
                result = first_error;          /* everyone settled: 0 if no errors */
        else
                return 0;

        return future_group_finalize(g, result);
}

static int future_group_cancel(sd_future *f) {
        return future_group_finalize(f, -ECANCELED);
}

static int future_group_set_priority(sd_future *f, int64_t priority) {
        FutureGroup *fg = ASSERT_PTR(sd_future_get_private(f));
        int r = 0;

        FOREACH_ARRAY(slot_p, fg->slots, fg->n_slots) {
                int q = sd_future_set_priority(sd_future_slot_get_future(*slot_p), priority);
                /* -EOPNOTSUPP: impl doesn't support priorities.
                 * -ESTALE: child already resolved — expected during a group's lifetime. */
                if (q < 0 && !IN_SET(q, -EOPNOTSUPP, -ESTALE))
                        RET_GATHER(r, q);
        }

        return r;
}

static const sd_future_ops future_group_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = future_group_alloc,
        .free = future_group_free,
        .cancel = future_group_cancel,
        .set_priority = future_group_set_priority,
};

int sd_future_group_new(sd_event *e, sd_future **ret) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(ret, -EINVAL);

        _cleanup_(sd_future_cancel_unrefp) sd_future *g = NULL;
        r = sd_future_new(e, &future_group_ops, &g);
        if (r < 0)
                return r;

        sd_future *parent = sd_fiber_get_current();
        if (parent) {
                FutureGroup *fg = sd_future_get_private(g);
                r = sd_future_add_callback(parent, &fg->parent_slot, future_group_parent_resolved, fg);
                if (r < 0)
                        return r;
                fg->parent = parent;
        }

        *ret = TAKE_PTR(g);
        return 0;
}

int sd_future_group_size(sd_future *f, size_t *ret) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &future_group_ops, -EINVAL);
        assert_return(ret, -EINVAL);

        FutureGroup *fg = sd_future_get_private(f);
        *ret = fg->n_slots;
        return 0;
}

int sd_future_group_set_policy(sd_future *f, uint64_t policy) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &future_group_ops, -EINVAL);
        assert_return(sd_future_state(f) == SD_FUTURE_PENDING, -ESTALE);
        assert_return((policy & ~(uint64_t)(SD_FUTURE_GROUP_WAIT_ANY | SD_FUTURE_GROUP_IGNORE_ERRORS)) == 0, -EINVAL);

        /* Policy must be configured before any children are added — once a child is in flight,
         * the resolution mechanics are locked in. This keeps the API friction-free: callers
         * don't have to reason about mid-flight reshuffling of which children get cancelled. */
        FutureGroup *fg = sd_future_get_private(f);
        if (fg->n_slots > 0)
                return -ESTALE;

        fg->policy = policy;
        return 0;
}

static int group_child_resolved(sd_future *child, void *userdata) {
        sd_future *g = ASSERT_PTR(userdata);
        return future_group_check(g);
}

int sd_future_group_add(sd_future *f, sd_future *child) {
        int r;

        assert_return(f, -EINVAL);
        assert_return(child, -EINVAL);
        assert_return(sd_future_get_ops(f) == &future_group_ops, -EINVAL);
        assert_return(sd_future_state(f) == SD_FUTURE_PENDING, -ESTALE);

        FutureGroup *fg = sd_future_get_private(f);
        if (fg->finalizing)
                /* Group is draining: a freshly-added pending child would have missed the
                 * cancel loop and hang us forever waiting for it to settle. */
                return -ESTALE;

        if (!GREEDY_REALLOC(fg->slots, fg->n_slots + 1))
                return -ENOMEM;

        sd_future_slot *slot = NULL;
        r = sd_future_add_callback(child, &slot, group_child_resolved, f);
        if (r < 0)
                return r;

        fg->slots[fg->n_slots++] = slot;

        return 0;
}

int sd_future_group_add_many_internal(sd_future *f, ...) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &future_group_ops, -EINVAL);

        FutureGroup *fg = sd_future_get_private(f);
        size_t before = fg->n_slots;
        int r = 0;

        va_list ap;
        va_start(ap, f);
        for (;;) {
                sd_future *child = va_arg(ap, sd_future*);
                if (!child)
                        break;

                r = sd_future_group_add(f, child);
                if (r < 0)
                        break;
        }
        va_end(ap);

        if (r < 0)
                /* Roll back this call's additions. */
                while (fg->n_slots > before) {
                        sd_future_slot_unref(fg->slots[--fg->n_slots]);
                        fg->slots[fg->n_slots] = NULL;
                }

        return r;
}

int sd_future_group_await(sd_future *f) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &future_group_ops, -EINVAL);

        /* Signal that someone is taking responsibility for the group's result via the await
         * path, so finalize() won't also cancel the parent fiber (which would replace the
         * group's real error with -ECANCELED). */
        FutureGroup *fg = sd_future_get_private(f);
        fg->parent_awaiting = true;

        return sd_fiber_await(f);
}

