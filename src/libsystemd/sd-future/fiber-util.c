/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>

#include "sd-future.h"

#include "errno-util.h"
#include "fiber-def.h"
#include "fiber-util.h"
#include "fiber.h"
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

int wait_for_terminate_suspend(pid_t pid, siginfo_t *ret) {
        Fiber *f = fiber_get_current();
        int r;

        assert(pid > 0);

        if (!f)
                return wait_for_terminate(pid, ret);

        assert(f->event);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = sd_future_new_child(f->event, pid, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate(pid, ret);
}

int wait_for_terminate_and_check_suspend(const char *name, pid_t pid, WaitFlags flags) {
        Fiber *f = fiber_get_current();
        int r;

        assert(pid > 0);

        if (!f)
                return wait_for_terminate_and_check(name, pid, flags);

        assert(f->event);

        _cleanup_(sd_future_unrefp) sd_future *child = NULL;
        r = sd_future_new_child(f->event, pid, WEXITED|WNOWAIT, &child);
        if (r < 0)
                return r;

        r = sd_future_set_callback(child, fiber_resume, f);
        if (r < 0)
                return r;

        r = fiber_suspend();
        if (r < 0)
                return r;

        return wait_for_terminate_and_check(name, pid, flags);
}

void sigkill_wait_suspend(pid_t pid) {
        Fiber *f = fiber_get_current();

        assert(pid > 1);

        if (!f) {
                sigkill_wait(pid);
                return;
        }

        (void) kill(pid, SIGKILL);
        (void) wait_for_terminate_suspend(pid, NULL);
}

void sigkill_wait_suspendp(pid_t *pid) {
        PROTECT_ERRNO;

        if (!pid)
                return;
        if (*pid <= 1)
                return;

        sigkill_wait_suspend(*pid);
}
