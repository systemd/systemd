/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>

#include "sd-future.h"

#include "fiber-def.h"
#include "fiber-util.h"
#include "fiber.h"
#include "future-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"

int fd_wait_for_event_suspend(int fd, int event, usec_t timeout) {
        struct pollfd pollfd = {
                .fd = fd,
                .events = event,
        };
        int r;

        r = sd_fiber_ppoll(&pollfd, 1, timeout);
        if (r <= 0)
                return r;

        return pollfd.revents;
}

int pidref_wait_for_terminate_suspend(PidRef *pidref, siginfo_t *ret) {
        Fiber *f = fiber_get_current();
        int r;

        if (!f)
                return pidref_wait_for_terminate(pidref, ret);

        assert(f->event);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = future_new_child_pidref(f->event, pidref, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return pidref_wait_for_terminate(pidref, ret);
}

int pidref_wait_for_terminate_and_check_suspend(const char *name, PidRef *pidref, WaitFlags flags) {
        Fiber *f = fiber_get_current();
        int r;

        if (!f)
                return pidref_wait_for_terminate_and_check(name, pidref, flags);

        assert(f->event);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = future_new_child_pidref(f->event, pidref, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return pidref_wait_for_terminate_and_check(name, pidref, flags);
}

void pidref_done_sigkill_wait_suspend(PidRef *pidref) {
        Fiber *f = fiber_get_current();

        if (!f) {
                pidref_done_sigkill_wait(pidref);
                return;
        }

        (void) pidref_kill(pidref, SIGKILL);
        (void) pidref_wait_for_terminate_suspend(pidref, /* ret= */ NULL);
}
