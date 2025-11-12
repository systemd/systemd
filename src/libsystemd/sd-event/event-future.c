/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-future.h"

typedef struct TimeFuture {
        sd_promise *promise;
        sd_event_source *source;
        uint64_t usec;

        /* Result the future resolves with on natural expiry (vs. cancellation). 0 for normal sleep,
         * non-zero (e.g. -ETIMEDOUT) lets a fiber waiting on this future resume with that error. */
        int result;
} TimeFuture;

static void* time_future_free(void *impl) {
        TimeFuture *f = impl;
        if (!f)
                return NULL;

        sd_event_source_unref(f->source);
        return mfree(f);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(TimeFuture*, time_future_free);

static int time_future_cancel(void *impl) {
        TimeFuture *f = ASSERT_PTR(impl);
        int r = sd_event_source_set_enabled(f->source, SD_EVENT_OFF);
        RET_GATHER(r, sd_promise_resolve(f->promise, -ECANCELED));
        return r;
}

static int time_future_set_priority(void *impl, int64_t priority) {
        TimeFuture *f = ASSERT_PTR(impl);
        return sd_event_source_set_priority(f->source, priority);
}

static const sd_future_ops time_future_ops = {
        .free = time_future_free,
        .cancel = time_future_cancel,
        .set_priority = time_future_set_priority,
};

static int time_handler(sd_event_source *s, usec_t usec, void *userdata) {
        TimeFuture *f = ASSERT_PTR(userdata);

        f->usec = usec;
        return sd_promise_resolve(f->promise, f->result);
}

int future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(time_future_freep) TimeFuture *impl = new(TimeFuture, 1);
        if (!impl)
                return -ENOMEM;

        *impl = (TimeFuture) {
                .result = result,
        };

        r = sd_event_add_time(e, &impl->source, clock, usec, accuracy, time_handler, impl);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(impl->source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        sd_future *f;
        r = sd_future_new(&time_future_ops, impl, &f);
        if (r < 0)
                return r;

        TAKE_PTR(impl);
        *ret = TAKE_PTR(f);
        return 0;
}

int future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(time_future_freep) TimeFuture *impl = new(TimeFuture, 1);
        if (!impl)
                return -ENOMEM;

        *impl = (TimeFuture) {
                .result = result,
        };

        r = sd_event_add_time_relative(e, &impl->source, clock, usec, accuracy, time_handler, impl);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(impl->source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        sd_future *f;
        r = sd_future_new(&time_future_ops, impl, &f);
        if (r < 0)
                return r;

        TAKE_PTR(impl);
        *ret = TAKE_PTR(f);
        return 0;
}
