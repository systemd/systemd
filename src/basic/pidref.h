/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* An embeddable structure carrying a reference to a process. Supposed to be used when tracking processes continously. */
typedef struct PidRef {
        pid_t pid; /* always valid */
        int fd;    /* only valid if pidfd are available in the kernel, and we manage to get an fd */
} PidRef;

#define PIDREF_NULL (PidRef) { .fd = -EBADF }

static inline bool pidref_is_set(const PidRef *pidref) {
        return pidref && pidref->pid > 0;
}

int pidref_set_pid(PidRef *pidref, pid_t pid);
int pidref_set_pidstr(PidRef *pidref, const char *pid);
int pidref_set_pidfd(PidRef *pidref, int fd);
int pidref_set_pidfd_take(PidRef *pidref, int fd); /* takes ownership of the passed pidfd on success*/
int pidref_set_pidfd_consume(PidRef *pidref, int fd); /* takes ownership of the passed pidfd in both success and failure */

void pidref_done(PidRef *pidref);

int pidref_kill(PidRef *pidref, int sig);
int pidref_kill_and_sigcont(PidRef *pidref, int sig);

#define TAKE_PIDREF(p) TAKE_GENERIC((p), PidRef, PIDREF_NULL)
