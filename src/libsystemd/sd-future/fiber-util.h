/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>     /* IWYU pragma: keep */

#include "sd-forward.h"

int fd_wait_for_event_suspend(int fd, int event, uint64_t timeout);

int pidref_wait_for_terminate_suspend(PidRef *pidref, siginfo_t *ret);
int pidref_wait_for_terminate_and_check_suspend(const char *name, PidRef *pidref, WaitFlags flags);

void pidref_done_sigkill_wait_suspend(PidRef *pid);
