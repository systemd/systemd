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
         * a ref on the slot. So `slots` is always a borrowed pointer collection regardless.
         *
         * Consequence of the non-floating case: because the slot holds a ref, dropping the slot may
         * perform the future's last unref — which, like any last unref, requires the future to already
         * be RESOLVED. A caller that releases its future handle and relies on the slot to keep the
         * future alive must drive it to resolution before dropping the slot. */
        sd_future *future;
        bool floating;

        sd_future_func_t callback;
        void *userdata;

        sd_event_source *defer_source;
        sd_event_source *exit_source;
};

struct sd_future {
        unsigned n_ref;

        int state;
        int result;

        sd_event *event;

        Set *slots;

        const sd_future_ops *ops;

        /* Opaque per-future state owned by the future implementation (the code that called
         * sd_future_new()). The ops vtable above receives this pointer in its callbacks, and
         * external code can fetch it via sd_future_get_private(). */
        void *private;
};

static int dispatch_slot(sd_future_slot *s, sd_future *f) {
        /* Invoked when the slot's chosen event source fires. Hold a self-ref on `f`
         * across the callback: a floating slot lives in f->slots, so if the callback
         * drops the last user-side ref to f, sd_future_free would iterate floating
         * slots and unref us — pulling the rug out from under the `sd_future_slot_unref`
         * below. Holding the ref keeps f alive until we've cleaned ourselves up; the
         * cleanup at scope exit drops it, freeing f if no one else held a ref. */
        bool floating = s->floating; /* capture: non-floating s may be freed by callback */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *self = sd_future_ref(f);

        int r = s->callback(f, s->userdata);
        if (floating)
                sd_future_slot_unref(s);
        return r;
}

static sd_event_source* slot_current_event_source(sd_future_slot *s) {
        assert(s);
        assert(s->future);

        return sd_event_get_state(s->future->event) == SD_EVENT_EXITING
                ? s->exit_source
                : s->defer_source;
}

static int slot_arm(sd_future_slot *s) {
        return sd_event_source_set_enabled(slot_current_event_source(s), SD_EVENT_ONESHOT);
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
        assert_return(f->state == SD_FUTURE_PENDING, -ESTALE);

        f->state = SD_FUTURE_RESOLVED;
        f->result = result;

        /* Enable each slot's currently-applicable event source so the callback fires on
         * the next loop iteration. The always-defer model frees the resolver from
         * reentrancy concerns, slot-set mutation during iteration, and callbacks dropping
         * the future's last ref. */
        sd_future_slot *s;
        SET_FOREACH(s, f->slots)
                RET_GATHER(r, slot_arm(s));

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
         * post-resolution via sd_future_add_callback — those are floating and may not have
         * had their defer tick yet.) Tear them down by dropping the future's ref. */
        Set *slots = TAKE_PTR(f->slots);
        sd_future_slot *s;
        SET_FOREACH(s, slots) {
                assert(s->floating);
                sd_future_slot_unref(s);
        }
        set_free(slots);

        if (f->ops->free)
                f->ops->free(f);

        sd_event_unref(f->event);
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
        if (r < 0)
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

                uint64_t before = sd_fiber_interrupt_count();
                r = sd_fiber_await(f);

                /* A negative await return is not necessarily a wait failure, so pick the message based
                 * on whether `f` actually finished. If `f` has resolved, the value is `f`'s own result
                 * — the wait succeeded, `f` just settled with an error. Otherwise the await was cut
                 * short before `f` finished (an outer SD_FIBER_TIMEOUT, a cancellation of the calling
                 * fiber, the event loop exiting, …) and we'll loop to keep driving `f` to resolution.
                 * -ECANCELED is the expected teardown outcome either way, so we don't log it. */
                if (sd_future_state(f) == SD_FUTURE_RESOLVED) {
                        int fr = sd_future_result(f);
                        if (fr < 0 && fr != -ECANCELED)
                                log_debug_errno(fr, "Future resolved with error, ignoring: %m");
                } else if (IN_SET(r, -ECANCELED, -ETIME))
                        log_debug_errno(r, "Interrupted while waiting for future to finish, deferring the interruption until the future resolves: %m");
                else if (r < 0)
                        log_debug_errno(r, "Failed to wait for future to finish, ignoring: %m");

                /* Remember an interruption value to re-queue. Only a value delivered as part of an
                 * interruption targeting *this* fiber (an explicit cancellation, an outer
                 * SD_FIBER_TIMEOUT firing, …) advances the count across the await; `f` simply resolving
                 * — even with a negative result like -ECANCELED — does not. So a negative return with an
                 * unchanged count is `f`'s own resolution surfacing through the resume callback, not an
                 * interruption, and must not be remembered: otherwise a later iteration where `f`
                 * resolves negative would clobber the value of an interruption seen earlier. */
                if (sd_fiber_interrupt_count() != before && r < 0)
                        q = r;

                if (sd_future_state(f) != SD_FUTURE_PENDING)
                        break;
        }

        /* Re-queue the interruption we held back, if any. */
        if (q < 0) {
                r = sd_fiber_resume(sd_fiber_get_current(), q);
                if (r < 0)
                        log_debug_errno(r, "Failed to re-queue interruption (%i) on calling fiber, ignoring: %m", q);
        }

        return sd_future_unref(f);
}

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_cancel_wait_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_cancel_wait_unref);

int sd_future_new(sd_event *e, const sd_future_ops *ops, sd_future **ret) {
        assert_return(e, -EINVAL);
        assert_return(ops, -EINVAL);
        assert_return(ops->size >= endoffsetof_field(sd_future_ops, set_priority), -EINVAL);
        assert_return(ops->alloc, -EINVAL);
        assert_return(ops->free, -EINVAL);
        assert_return(ops->cancel, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_future *f = new(sd_future, 1);
        if (!f)
                return -ENOMEM;

        *f = (sd_future) {
                .n_ref = 1,
                .state = SD_FUTURE_PENDING,
                .ops = ops,
                .event = sd_event_ref(e),
        };

        f->private = ops->alloc();
        if (!f->private) {
                sd_event_unref(f->event);
                free(f);
                return -ENOMEM;
        }

        *ret = f;
        return 0;
}

sd_event* sd_future_get_event(sd_future *f) {
        assert_return(f, NULL);
        return f->event;
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
                if (!s->floating) {
                        /* A non-floating slot owns a ref on its future, so this may be the last unref.
                         * Like any last unref it requires the future to already be RESOLVED — dropping a
                         * slot must never be what abandons a still-PENDING future. Assert here so the
                         * misuse points at the slot drop rather than surfacing as the generic
                         * sd_future_free() assert. */
                        assert(s->future->n_ref > 1 || s->future->state == SD_FUTURE_RESOLVED);
                        sd_future_unref(s->future);
                }
        }

        sd_event_source_disable_unref(s->defer_source);
        sd_event_source_disable_unref(s->exit_source);

        return mfree(s);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_future_slot, sd_future_slot, sd_future_slot_free);

static int slot_dispatch_handler(sd_event_source *src, void *userdata) {
        sd_future_slot *s = ASSERT_PTR(userdata);
        return dispatch_slot(s, s->future);
}

int sd_future_add_callback(sd_future *f, sd_future_slot **ret_slot, sd_future_func_t callback, void *userdata) {
        int r;

        assert_return(f, -EINVAL);
        assert_return(callback, -EINVAL);

        _cleanup_(sd_future_slot_unrefp) sd_future_slot *s = new(sd_future_slot, 1);
        if (!s)
                return -ENOMEM;

        *s = (sd_future_slot) {
                .n_ref = 1,
                .future = f,
                .floating = ret_slot == NULL,
                .callback = callback,
                .userdata = userdata,
        };

        /* Asymmetric ownership (same trick as sd_bus_slot): non-floating slot owns the
         * future, floating slot is owned by it — avoids a cycle in either direction. */
        if (!s->floating)
                sd_future_ref(f);

        /* Never run the callback inline, always use a defer event source to schedule it,
         * even if the future is already resolved. This simplifies callers which now don't
         * have to worry about the callback being potentially called inline. */

        r = sd_event_add_defer(f->event, &s->defer_source, slot_dispatch_handler, s);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s->defer_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        r = sd_event_add_exit(f->event, &s->exit_source, slot_dispatch_handler, s);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s->exit_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                int64_t priority;
                if (sd_fiber_get_priority(&priority) >= 0) {
                        (void) sd_event_source_set_priority(s->defer_source, priority);
                        (void) sd_event_source_set_priority(s->exit_source, priority);
                }
        }

        if (f->state == SD_FUTURE_RESOLVED) {
                r = slot_arm(s);
                if (r < 0)
                        return r;
        }

        r = set_ensure_put(&f->slots, &trivial_hash_ops, s);
        if (r < 0)
                return r;

        if (!s->floating)
                *ret_slot = s;

        TAKE_PTR(s);
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

        if (f->state == SD_FUTURE_RESOLVED)
                return 0;

        return f->ops->cancel(f);
}
