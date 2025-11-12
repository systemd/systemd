/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fiber-def.h"
#include "log.h"
#include "macro.h"
#include "set.h"

/* sd_promise is the write side of a future — the only handle that can resolve it. It's embedded
 * inside sd_future (opaque from the outside; just a marker type), and we recover the containing
 * sd_future via container_of() when the promise is resolved. */
struct sd_promise {};

struct sd_future {
        sd_promise promise;

        unsigned n_ref;

        int state;
        int result;

        Set *waiters;

        sd_future_func_t callback;
        void *userdata;

        const sd_future_ops *ops;
        void *impl;
};

static int fiber_resume_trampoline(sd_future *f) {
        /* The future's result is what the fiber should resume with. Impls choose the value at
         * resolution time — e.g. a deadline timer resolves with -ETIME, a wait future resolves
         * with the target's result, a normal IO/sleep future resolves with 0 on success. */
        return sd_fiber_resume(sd_future_get_userdata(f), sd_future_result(f));
}

int sd_promise_resolve(sd_promise *p, int result) {
        sd_future *f = container_of(p, sd_future, promise);
        int r = 0;

        assert(f);

        if (f->state != SD_FUTURE_PENDING)
                return 0;

        f->state = SD_FUTURE_RESOLVED;
        f->result = result;

        if (f->callback)
                RET_GATHER(r, f->callback(f));

        sd_promise *w;
        SET_FOREACH(w, f->waiters)
                RET_GATHER(r, sd_promise_resolve(w, result));

        f->waiters = set_free(f->waiters);

        return r;
}

static sd_future* sd_future_free(sd_future *f) {
        if (!f)
                return NULL;

        if (f->state == SD_FUTURE_PENDING)
                sd_promise_resolve(&f->promise, -ECANCELED);

        set_free(f->waiters);

        if (f->ops->free)
                f->ops->free(f->impl);

        return mfree(f);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_future, sd_future, sd_future_free);
DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_unref);

sd_future* sd_future_cancel_wait_unref(sd_future *f) {
        int r;

        if (!f)
                return NULL;

        /* We have to be able to suspend until the fiber we're waiting for finishes, and that's only
         * possible if we're running on a fiber ourselves. */
        assert(sd_fiber_is_running());

        r = sd_future_cancel(f);
        if (r < 0)
                log_debug_errno(r, "Failed to cancel future, ignoring: %m");

        if (f->state == SD_FUTURE_PENDING) {
                /* Fast path: when f's resolve callback already targets the current fiber (the default for
                 * futures created on this fiber), we can suspend directly and let the existing trampoline
                 * wake us up — no need to allocate a wait future just to learn about the resolution.
                 * Otherwise fall back to sd_fiber_await() which sets up an explicit waiter. */
                if (f->callback == fiber_resume_trampoline && f->userdata == sd_fiber_get_current())
                        r = sd_fiber_suspend();
                else
                        r = sd_fiber_await(f);
                if (r < 0 && r != -ECANCELED)
                        log_debug_errno(r, "Failed to wait for future to finish, ignoring: %m");
        }

        return sd_future_unref(f);
}

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_cancel_wait_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_cancel_wait_unref);

int sd_future_new(const sd_future_ops *ops, void *impl, sd_future **ret) {
        assert(ops);
        assert(impl);
        assert(ret);

        sd_future *f = new(sd_future, 1);
        if (!f)
                return -ENOMEM;

        *f = (sd_future) {
                .n_ref = 1,
                .state = SD_FUTURE_PENDING,
                .ops = ops,
                .impl = impl,
        };

        /* By convention the first field of any impl struct is `sd_promise *promise` so handlers that
         * receive the impl pointer can resolve the future without a separate lookup. Stamp the
         * back-pointer here so the caller doesn't have to. */
        *(sd_promise **) impl = &f->promise;

        /* If we're being created on a fiber, default the callback to resuming that fiber on resolve —
         * this is almost always what you want, and it saves the usual set_callback boilerplate before
         * sd_fiber_suspend(). Callers that want different behavior can override with
         * sd_future_set_callback(). */
        sd_future *fiber = sd_fiber_get_current();
        if (fiber)
                (void) sd_future_set_callback(f, fiber_resume_trampoline, fiber);

        *ret = f;
        return 0;
}

int sd_future_state(sd_future *f) {
        assert(f);
        return f->state;
}

int sd_future_result(sd_future *f) {
        assert(f);
        assert(f->state == SD_FUTURE_RESOLVED);
        return f->result;
}

void* sd_future_get_userdata(sd_future *f) {
        assert(f);
        return f->userdata;
}

void* sd_future_get_impl(sd_future *f) {
        assert(f);
        return f->impl;
}

const sd_future_ops* sd_future_get_ops(sd_future *f) {
        assert(f);
        return f->ops;
}

int sd_future_set_callback(sd_future *f, sd_future_func_t callback, void *userdata) {
        assert(f);

        f->callback = callback;
        f->userdata = userdata;
        return 0;
}

int sd_future_set_priority(sd_future *f, int64_t priority) {
        assert(f);
        assert(f->state == SD_FUTURE_PENDING);
        assert(f->ops->set_priority);

        return f->ops->set_priority(f->impl, priority);
}

int sd_future_cancel(sd_future *f) {
        assert(f);
        assert(f->ops->cancel);

        if (f->state == SD_FUTURE_RESOLVED)
                return 0;

        return f->ops->cancel(f->impl);
}

sd_future* sd_fiber_get_current(void) {
        Fiber *f = fiber_get_current();
        return f ? container_of(f->promise, sd_future, promise) : NULL;
}

typedef struct WaitFuture {
        sd_promise *promise;
        sd_future *target;
} WaitFuture;

static void* wait_future_free(void *impl) {
        WaitFuture *f = impl;
        if (!f)
                return NULL;

        if (f->target) {
                set_remove(f->target->waiters, f->promise);
                sd_future_unref(f->target);
        }

        return mfree(f);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(WaitFuture*, wait_future_free);

static int wait_future_cancel(void *impl) {
        WaitFuture *f = ASSERT_PTR(impl);

        set_remove(f->target->waiters, f->promise);
        return sd_promise_resolve(f->promise, -ECANCELED);
}

static const sd_future_ops wait_future_ops = {
        .free = wait_future_free,
        .cancel = wait_future_cancel,
};

int sd_future_new_wait(sd_future *target, sd_future **ret) {
        int r;

        assert(target);
        assert(ret);

        _cleanup_(wait_future_freep) WaitFuture *impl = new(WaitFuture, 1);
        if (!impl)
                return -ENOMEM;

        *impl = (WaitFuture) {
                .target = sd_future_ref(target),
        };

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&wait_future_ops, impl, &f);
        if (r < 0)
                return r;

        TAKE_PTR(impl);

        if (target->state == SD_FUTURE_RESOLVED)
                r = sd_promise_resolve(&f->promise, target->result);
        else
                r = set_ensure_put(&target->waiters, &trivial_hash_ops, &f->promise);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}
