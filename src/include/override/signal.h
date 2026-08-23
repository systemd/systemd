/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <signal.h>        /* IWYU pragma: export */

/* Defined since glibc-2.39. */
#ifndef SEGV_CPERR
#define SEGV_CPERR 10
#endif

#ifndef SI_DETHREAD
#define SI_DETHREAD -7
#endif

/* Defined since glibc-2.43. */
#ifndef TRAP_PERF
#define TRAP_PERF 6
#endif

/* Defined since glibc-2.33. */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

int rt_tgsigqueueinfo_shim(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
#define rt_tgsigqueueinfo rt_tgsigqueueinfo_shim
