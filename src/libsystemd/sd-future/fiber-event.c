/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "fiber.h"
#include "fiber-def.h"

int sd_event_run_suspend(sd_event *e, uint64_t timeout) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(e);
        assert(f->event);

        r = sd_event_prepare(e);
        if (r < 0)
                return r;
        if (r == 0) {
                r = sd_event_wait(e, 0);
                if (r < 0)
                        return r;
        }
        if (r > 0)
                return sd_event_dispatch(e);

        if (timeout == 0)
                return 0;

        r = sd_event_prepare(e);
        if (r < 0)
                return r;

        int fd = sd_event_get_fd(e);
        if (fd < 0)
                return fd;

        _cleanup_(sd_future_unrefp) sd_future *io = NULL;
        r = sd_future_new_io(f->event, fd, EPOLLIN, &io);
        if (r < 0)
                return r;

        r = sd_future_set_callback(io, fiber_resume, f);
        if (r < 0)
                return r;

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        if (timeout != USEC_INFINITY) {
                r = sd_future_new_time_relative(f->event, CLOCK_MONOTONIC, timeout, /* accuracy= */ 1, &timer);
                if (r < 0)
                        return r;

                r = sd_future_set_callback(timer, fiber_resume, f);
                if (r < 0)
                        return r;
        }

        r = fiber_suspend();
        if (r < 0)
                return r;

        r = sd_event_wait(e, 0);
        if (r <= 0)
                return r;

        return sd_event_dispatch(e);
}
