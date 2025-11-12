/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "macro.h"
#include "set.h"

struct sd_future {
        unsigned n_ref;

        int state;
        int result;

        Set *waiters;

        sd_future_func_t callback;
        void *userdata;

        const sd_future_ops *ops;

        /* Opaque per-future state owned by the future implementation (the code that called
         * sd_future_new()). The ops vtable above receives this pointer in its callbacks, and
         * external code can fetch it via sd_future_get_private(). */
        void *private;
};

static int fiber_resume_trampoline(sd_future *f) {
        /* The future's result is what the fiber should resume with. Impls choose the value at
         * resolution time — e.g. a deadline timer resolves with -ETIME, a wait future resolves
         * with the target's result, a normal IO/sleep future resolves with 0 on success. */
        return sd_fiber_resume(sd_future_get_userdata(f), sd_future_result(f));
}

int sd_future_resolve(sd_future *f, int result) {
        int r = 0;

        assert_return(f, -EINVAL);

        if (f->state != SD_FUTURE_PENDING)
                return 0;

        f->state = SD_FUTURE_RESOLVED;
        f->result = result;

        if (f->callback)
                RET_GATHER(r, f->callback(f));

        sd_future *w;
        SET_FOREACH(w, f->waiters)
                RET_GATHER(r, sd_future_resolve(w, result));

        f->waiters = set_free(f->waiters);

        return r;
}

static sd_future* sd_future_free(sd_future *f) {
        if (!f)
                return NULL;

        if (f->state == SD_FUTURE_PENDING)
                sd_future_resolve(f, -ECANCELED);

        set_free(f->waiters);

        if (f->ops->free)
                f->ops->free(f);

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
        assert_return(sd_fiber_is_running(), NULL);

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
        assert_return(f, -EINVAL);
        return f->state;
}

int sd_future_result(sd_future *f) {
        assert_return(f, -EINVAL);
        assert_return(f->state == SD_FUTURE_RESOLVED, -EBUSY);
        return f->result;
}

void* sd_future_get_userdata(sd_future *f) {
        assert_return(f, NULL);
        return f->userdata;
}

void* sd_future_get_private(sd_future *f) {
        assert_return(f, NULL);
        return f->private;
}

const sd_future_ops* sd_future_get_ops(sd_future *f) {
        assert_return(f, NULL);
        return f->ops;
}

int sd_future_set_callback(sd_future *f, sd_future_func_t callback, void *userdata) {
        assert_return(f, -EINVAL);

        f->callback = callback;
        f->userdata = userdata;
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

typedef struct WaitFuture {
        sd_future *target;
} WaitFuture;

static void* wait_future_alloc(void) {
        return new0(WaitFuture, 1);
}

static void wait_future_free(sd_future *f) {
        WaitFuture *wf = sd_future_get_private(f);

        if (wf->target)
                set_remove(wf->target->waiters, f);

        sd_future_unref(wf->target);
        free(wf);
}

static int wait_future_cancel(sd_future *f) {
        WaitFuture *wf = ASSERT_PTR(sd_future_get_private(f));

        set_remove(wf->target->waiters, f);
        return sd_future_resolve(f, -ECANCELED);
}

static const sd_future_ops wait_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = wait_future_alloc,
        .free = wait_future_free,
        .cancel = wait_future_cancel,
};

int sd_future_new_wait(sd_future *target, sd_future **ret) {
        int r;

        assert_return(target, -EINVAL);
        assert_return(ret, -EINVAL);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&wait_future_ops, &f);
        if (r < 0)
                return r;

        WaitFuture *wf = sd_future_get_private(f);
        wf->target = sd_future_ref(target);

        if (target->state == SD_FUTURE_RESOLVED)
                r = sd_future_resolve(f, target->result);
        else
                r = set_ensure_put(&target->waiters, &trivial_hash_ops, f);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}
