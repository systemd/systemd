/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-future.h"

typedef struct TimeFuture {
        sd_event_source *source;

        /* Result the future resolves with on natural expiry (vs. cancellation). 0 for normal sleep,
         * non-zero (e.g. -ETIMEDOUT) lets a fiber waiting on this future resume with that error. */
        int result;
} TimeFuture;

static void* time_future_alloc(void) {
        return new0(TimeFuture, 1);
}

static void time_future_free(sd_future *f) {
        TimeFuture *tf = sd_future_get_private(ASSERT_PTR(f));
        sd_event_source_unref(tf->source);
        free(tf);
}

static int time_future_cancel(sd_future *f) {
        TimeFuture *tf = sd_future_get_private(ASSERT_PTR(f));
        int r = sd_event_source_set_enabled(tf->source, SD_EVENT_OFF);
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int time_future_set_priority(sd_future *f, int64_t priority) {
        TimeFuture *tf = sd_future_get_private(ASSERT_PTR(f));
        return sd_event_source_set_priority(tf->source, priority);
}

static const sd_future_ops time_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = time_future_alloc,
        .free = time_future_free,
        .cancel = time_future_cancel,
        .set_priority = time_future_set_priority,
};

static int time_handler(sd_event_source *s, usec_t usec, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        TimeFuture *tf = sd_future_get_private(f);

        return sd_future_resolve(f, tf->result);
}

int future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&time_future_ops, &f);
        if (r < 0)
                return r;

        TimeFuture *tf = sd_future_get_private(f);
        tf->result = result;

        r = sd_event_add_time(e, &tf->source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                int64_t priority;

                r = sd_fiber_get_priority(&priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(tf->source, priority);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&time_future_ops, &f);
        if (r < 0)
                return r;

        TimeFuture *tf = sd_future_get_private(f);
        tf->result = result;

        r = sd_event_add_time_relative(e, &tf->source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                int64_t priority;

                r = sd_fiber_get_priority(&priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(tf->source, priority);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}
