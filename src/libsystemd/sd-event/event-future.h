/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h> /* IWYU pragma: keep */

#include "forward.h"

/* Event/future integration, implemented using only the public sd-future API. */

int future_new_io(sd_event *e, int fd, uint32_t events, sd_future **ret);
int future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret);
int future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret);
/* Resolves with 0 once the child reports one of the waitid() events in options. The process must be a
 * child of the caller and is reaped when the future resolves, unless WNOWAIT is set. Cancellation only
 * stops watching: the process keeps running and stays unreaped. */
int future_new_child(sd_event *e, const PidRef *pidref, int options, sd_future **ret);
/* Available once the process reported the event, even if the future resolved with -ECANCELED. */
int future_child_get_siginfo(sd_future *f, siginfo_t *ret);
/* Opt into owning the process: cancellation then terminates it instead of dropping the wait, sending
 * SIGTERM on the first attempt and SIGKILL on the next, or once the kill timeout has passed, whichever
 * comes first. The future stays pending until the process has exited, resolving with -ECANCELED.
 * Cancellation hence becomes asynchronous: await it with sd_future_cancel_wait_unref(), whose retry
 * loop escalates once its wait is interrupted, so a fiber timeout scope can shorten the grace period.
 * Only available for plain WEXITED futures: ownership has to see the process exit and reap it. */
int future_child_set_process_own(sd_future *f, int own);
/* Grace period between SIGTERM and SIGKILL, DEFAULT_TIMEOUT_USEC unless set. USEC_INFINITY disables the
 * timer, leaving escalation to a second cancellation. Takes effect on the next cancellation. */
int future_child_set_kill_timeout(sd_future *f, uint64_t usec);

int future_group_add_io(sd_future *group, int fd, uint32_t events);
int future_group_add_time_relative(sd_future *group, clockid_t clock, uint64_t usec, uint64_t accuracy, int result);
int future_group_add_child(sd_future *group, const PidRef *pidref, int options);

int event_source_inherit_fiber_priority(sd_event_source *s);

int event_run_suspend(sd_event *e, uint64_t timeout);
