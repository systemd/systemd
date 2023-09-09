/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* An embeddable structure carrying a reference to a process. Supposed to be used when tracking processes continously. */
typedef struct PidRef {
        pid_t pid; /* always valid */
        int fd;    /* only valid if pidfd are available in the kernel, and we manage to get an fd */
} PidRef;

#define PIDREF_INIT (PidRef) { .fd = -EBADF }

static inline bool pidref_is_set(const PidRef *pidref) {
        return pidref && pidref->pid > 0;
}

int pidref_set_pid(PidRef *pidref, pid_t pid);
int pidref_set_pidfd(PidRef *pidref, int fd);
int pidref_set_pidfd_take(PidRef *pidref, int fd); /* takes ownership of the passed pidfd */

PidRef* pidref_done(PidRef *pidref);

int pidref_kill(PidRef *pidref, int sig);
int pidref_kill_and_sigcont(PidRef *pidref, int sig);

DEFINE_TRIVIAL_CLEANUP_FUNC(PidRef*, pidref_done);

#define TAKE_PIDREF(p) ({ PidRef t = (p); (p) = PIDREF_INIT; t; })
