/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* sched.h includes linux/sched/types.h since glibc-2.41. */
#include <linux/sched/types.h>

#include_next <sched.h>

/* 769071ac9f20b6a447410c7eaa55d1a5233ef40c (5.8),
 * defined in sched.h since glibc-2.36. */
#ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME 0x00000080
#endif

/* Not exposed yet. Defined at include/linux/sched.h */
#ifndef PF_KTHREAD
#  define PF_KTHREAD 0x00200000
#endif

/* The maximum thread/process name length including trailing NUL byte. This mimics the kernel definition of
 * the same name, which we need in userspace at various places but is not defined in userspace currently,
 * neither under this name nor any other.
 *
 * Not exposed yet. Defined at include/linux/sched.h */
#ifndef TASK_COMM_LEN
#  define TASK_COMM_LEN 16
#endif
