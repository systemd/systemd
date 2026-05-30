/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "macro.h"
#include "set.h"

struct sd_future_slot {
        unsigned n_ref;

        /* Back-pointer to the future the slot is attached to.
         *
         * Ref ownership is asymmetric (same trick as sd_bus_slot/bus->slots): when the slot
         * is non-floating the SLOT owns a ref on the future; when floating, the FUTURE owns
         * a ref on the slot. So `slots` is always a borrowed pointer collection regardless. */
        sd_future *future;
        bool floating;

        sd_future_func_t callback;
        void *userdata;

        /* When `future` is already RESOLVED at sd_future_add_callback time and we're on a
         * fiber, the slot can't ride on `future`'s normal slot-dispatch (that path is in the
         * past). Instead the slot owns a dedicated defer event source that fires on the next
         * loop tick and invokes `callback` directly via slot_defer_handler. NULL otherwise. */
        sd_event_source *defer_source;
};

struct sd_future {
        unsigned n_ref;

        int state;
        int result;

        Set *slots;

        const sd_future_ops *ops;

        /* Opaque per-future state owned by the future implementation (the code that called
         * sd_future_new()). The ops vtable above receives this pointer in its callbacks, and
         * external code can fetch it via sd_future_get_private(). */
        void *private;
};

static int dispatch_slot(sd_future_slot *s, sd_future *f) {
        /* Single funnel for invoking a slot's callback and tearing down its floating-side
         * ref. Used by sd_future_resolve's slot-dispatch loop (where `f` is the future
         * being resolved) and by slot_defer_handler (where `f` is the slot's own future,
         * already RESOLVED, and the defer source just provides the one-tick delay). */
        bool floating = s->floating; /* capture: non-floating s may be freed by callback */
        int r = s->callback(f, s->userdata);
        if (floating)
                sd_future_slot_unref(s);
        return r;
}

int sd_future_resume_callback(sd_future *f, void *userdata) {
        /* The future's result is what the fiber should resume with. Impls choose the value at
         * resolution time — e.g. a deadline timer resolves with -ETIME, a wait future resolves
         * with the target's result, a normal IO/sleep future resolves with 0 on success. */
        return sd_fiber_resume(userdata, sd_future_result(f));
}

int sd_future_resolve(sd_future *f, int result) {
        int r = 0;

        assert_return(f, -EINVAL);

        if (f->state != SD_FUTURE_PENDING)
                return 0;

        /* Hold a self-ref across callback dispatch: callbacks may legitimately release what
         * would otherwise be the last reference, and we still access f->slots below. The
         * cleanup unrefs at scope exit, which is when freeing is safe again. */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *self = sd_future_ref(f);

        f->state = SD_FUTURE_RESOLVED;
        f->result = result;

        /* Take ownership of the dispatch set so callbacks can mutate it (including freeing
         * their own slot) without invalidating iteration. Non-floating slots keep their
         * back-pointer to `f` — they may still be inspected by callbacks (e.g.
         * sd_future_group walks its slot vector to gather child results), and a later
         * user-side sd_future_slot_unref finds f->slots NULL and skips set_remove
         * harmlessly. Floating slots get torn down here: the user has no handle on them,
         * so their callback can't have unref'd them, and dropping the future's claim
         * frees them. */
        Set *slots = TAKE_PTR(f->slots);
        sd_future_slot *s;
        SET_FOREACH(s, slots)
                RET_GATHER(r, dispatch_slot(s, f));
        set_free(slots);

        return r;
}

static sd_future* sd_future_free(sd_future *f) {
        /* By the time we tear down, the future must have reached a terminal state. Callers
         * abandoning a still-PENDING future must drive it to RESOLVED first — typically via
         * sd_future_cancel_unref() (non-fiber, synchronous-cancel impls) or
         * sd_future_cancel_wait_unref() (fiber, awaits actual resolution).. */
        assert(f->state == SD_FUTURE_RESOLVED);

        /* Any slot still in f->slots at this point must be floating: non-floating slots own
         * a ref on f, so if any existed we wouldn't have reached free. (Slots can be added
         * post-resolution via sd_future_add_callback from a fiber — those are floating and
         * may not have had their defer tick yet.) Tear them down by dropping the future's
         * ref. */
        Set *slots = TAKE_PTR(f->slots);
        sd_future_slot *s;
        SET_FOREACH(s, slots) {
                assert(s->floating);
                sd_future_slot_unref(s);
        }
        set_free(slots);

        if (f->ops->free)
                f->ops->free(f);

        return mfree(f);
}

/* Unref is a pure refcount op: dropping a ref does not resolve or cancel. If a caller wants
 * pending work to complete (and floating callbacks to observe the outcome) before release,
 * they must drive resolution explicitly — typically via sd_future_cancel() or
 * sd_future_cancel_wait_unref(). Reaching sd_future_free() with state PENDING is a programming
 * error and trips an assert: callers must drive the future to RESOLVED before dropping the last
 * ref. */
DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_future, sd_future, sd_future_free);

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_unref);

sd_future* sd_future_cancel_unref(sd_future *f) {
        int r;

        if (!f)
                return NULL;

        /* Synchronous-cancel teardown for non-fiber contexts: drive the future to RESOLVED via
         * ops->cancel, then drop the ref. Safe for impls whose ops->cancel resolves synchronously.
         * For impls whose cancel is asynchronous, the future stays PENDING after this call and
         * sd_future_free's strict assert will trip. Callers in that situation must use
         * sd_future_cancel_wait_unref() from a fiber to await the actual resolution. */
        r = sd_future_cancel(f);
        if (r < 0 && r != -EOPNOTSUPP)
                log_debug_errno(r, "Failed to cancel future, ignoring: %m");

        return sd_future_unref(f);
}

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_cancel_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_cancel_unref);

sd_future* sd_future_cancel_wait_unref(sd_future *f) {
        int r, q = 0;

        if (!f)
                return NULL;

        /* Caller must be on a fiber: the wait step parks the calling fiber on the future until it
         * actually resolves. Callers without a fiber should use sd_future_cancel_unref(), which
         * works for impls whose cancel is synchronous. */
        assert(sd_fiber_is_running());

        for (;;) {
                r = sd_future_cancel(f);
                if (r < 0)
                        log_debug_errno(r, "Failed to cancel future, ignoring: %m");

                if (sd_future_state(f) != SD_FUTURE_PENDING)
                        break;

                r = sd_fiber_await(f);
                if (r < 0) {
                        if (r != -ECANCELED)
                                log_debug_errno(r, "Failed to wait for future to finish, ignoring: %m");
                        /* The await was interrupted by something targeting the calling fiber (a
                         * cancellation, an outer SD_FIBER_TIMEOUT firing, …). We have to keep looping
                         * until `f` actually resolves so unref is safe, so we can't honor it inline
                         * — but we mustn't drop it either. Remember the most recent one and re-queue
                         * it on the fiber once just before we return. */
                        q = r;
                }

                if (sd_future_state(f) != SD_FUTURE_PENDING)
                        break;
        }

        if (q < 0) {
                r = sd_fiber_resume(sd_fiber_get_current(), q);
                if (r < 0)
                        log_debug_errno(r, "Failed to re-queue interruption (%i) on calling fiber, ignoring: %m", q);
        }

        return sd_future_unref(f);
}

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_cancel_wait_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_cancel_wait_unref);

int sd_future_new(const sd_future_ops *ops, sd_future **ret) {
        assert_return(ops, -EINVAL);
        assert_return(ops->size >= endoffsetof_field(sd_future_ops, set_priority), -EINVAL);
        assert_return(ops->alloc, -EINVAL);
        assert_return(ops->free, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_future *f = new(sd_future, 1);
        if (!f)
                return -ENOMEM;

        *f = (sd_future) {
                .n_ref = 1,
                .state = SD_FUTURE_PENDING,
                .ops = ops,
        };

        f->private = ops->alloc();
        if (!f->private) {
                free(f);
                return -ENOMEM;
        }

        *ret = f;
        return 0;
}

int sd_future_state(sd_future *f) {
        assert_return(f, -EINVAL);
        return f->state;
}

int sd_future_result(sd_future *f) {
        assert_return(f, -EINVAL);
        assert_return(f->state == SD_FUTURE_RESOLVED, -EBUSY);
        return f->result;
}

void* sd_future_get_private(sd_future *f) {
        assert_return(f, NULL);
        return f->private;
}

const sd_future_ops* sd_future_get_ops(sd_future *f) {
        assert_return(f, NULL);
        return f->ops;
}

sd_future* sd_future_slot_get_future(sd_future_slot *s) {
        assert_return(s, NULL);
        return s->future;
}

static sd_future_slot* sd_future_slot_free(sd_future_slot *s) {
        if (!s)
                return NULL;

        if (s->future) {
                set_remove(s->future->slots, s);
                if (!s->floating)
                        sd_future_unref(s->future);
        }

        sd_event_source_disable_unref(s->defer_source);

        return mfree(s);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_future_slot, sd_future_slot, sd_future_slot_free);

static int slot_defer_handler(sd_event_source *src, void *userdata) {
        sd_future_slot *s = ASSERT_PTR(userdata);
        return dispatch_slot(s, s->future);
}

int sd_future_add_callback(sd_future *f, sd_future_slot **ret_slot, sd_future_func_t callback, void *userdata) {
        int r;

        assert_return(f, -EINVAL);
        assert_return(callback, -EINVAL);

        if (f->state == SD_FUTURE_RESOLVED && !sd_fiber_is_running()) {
                /* Inline: run synchronously now. Hand back a no-op slot so callers have a
                 * uniform "got a slot" handle to manage. */
                r = callback(f, userdata);
                if (r < 0)
                        return r;

                if (ret_slot) {
                        sd_future_slot *s = new(sd_future_slot, 1);
                        if (!s)
                                return -ENOMEM;

                        *s = (sd_future_slot) {
                                .n_ref = 1,
                                .future = sd_future_ref(f),
                        };

                        *ret_slot = s;
                }

                return 0;
        }

        sd_future_slot *s = new(sd_future_slot, 1);
        if (!s)
                return -ENOMEM;

        *s = (sd_future_slot) {
                .n_ref = 1,
                .future = f,
                .floating = ret_slot == NULL,
                .callback = callback,
                .userdata = userdata,
        };

        if (f->state == SD_FUTURE_RESOLVED) {
                /* Future already resolved, but we prefer to not invoke the callback inline if possible to
                 * make sure the callback always runs in the same environment (not on the current fiber). To
                 * make this work we use a defer event source instead which invokes the callback on the next
                 * tick. */
                r = sd_event_add_defer(sd_fiber_get_event(), &s->defer_source, slot_defer_handler, s);
                if (r < 0) {
                        free(s);
                        return r;
                }

                int64_t priority;
                r = sd_fiber_get_priority(&priority);
                if (r >= 0)
                        (void) sd_event_source_set_priority(s->defer_source, priority);
        }

        /* Asymmetric ownership: non-floating slot owns the future; floating slot is owned
         * by the future (avoids a refcount cycle in both directions). The slot's initial
         * n_ref=1 from construction is the one ref that gets transferred — to the user via
         * ret_slot for non-floating, or to the future (via membership in f->slots) for
         * floating. For the defer-source path, slot_defer_handler drops the floating slot's
         * ref after firing, which frees it. */
        if (!s->floating)
                sd_future_ref(f);

        r = set_ensure_put(&f->slots, &trivial_hash_ops, s);
        if (r < 0) {
                sd_future_slot_unref(s);
                return r;
        }

        if (!s->floating)
                *ret_slot = s;

        return 0;
}

int sd_future_set_priority(sd_future *f, int64_t priority) {
        assert_return(f, -EINVAL);
        assert_return(f->state == SD_FUTURE_PENDING, -ESTALE);
        assert_return(f->ops->set_priority, -EOPNOTSUPP);

        return f->ops->set_priority(f, priority);
}

int sd_future_cancel(sd_future *f) {
        assert_return(f, -EINVAL);
        assert_return(f->ops->cancel, -EOPNOTSUPP);

        if (f->state == SD_FUTURE_RESOLVED)
                return 0;

        return f->ops->cancel(f);
}
