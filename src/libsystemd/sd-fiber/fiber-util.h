/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>

#include "sd-fiber.h"           /* IWYU pragma: export */
#include "sd-forward.h"

int fd_wait_for_event_suspend(int fd, int event, uint64_t timeout);

int wait_for_terminate_suspend(pid_t pid, siginfo_t *ret);
int wait_for_terminate_and_check_suspend(const char *name, pid_t pid, WaitFlags flags);
int wait_for_terminate_with_timeout_suspend(pid_t pid, usec_t timeout);

void sigkill_wait_suspend(pid_t pid);
void sigkill_wait_suspendp(pid_t *pid);
