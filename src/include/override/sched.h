/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* sched.h includes linux/sched/types.h since glibc-2.41 (21571ca0d70302909cf72707b2a7736cf12190a0),
 * to make struct sched_attr being defined.
 * Note, this must be included before sched.h, otherwise the headers conflict with each other. */
#include <linux/sched/types.h>

#include_next <sched.h>

#include <assert.h>

/* 769071ac9f20b6a447410c7eaa55d1a5233ef40c (5.8),
 * defined in sched.h since glibc-2.36. */
#ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME 0x00000080
#else
static_assert(CLONE_NEWTIME == 0x00000080, "");
#endif

/* Not exposed yet. Defined at include/linux/sched.h */
#ifndef PF_KTHREAD
#  define PF_KTHREAD 0x00200000
#else
static_assert(PF_KTHREAD == 0x00200000, "");
#endif

/* The maximum thread/process name length including trailing NUL byte. This mimics the kernel definition of
 * the same name, which we need in userspace at various places but is not defined in userspace currently,
 * neither under this name nor any other.
 *
 * Not exposed yet. Defined at include/linux/sched.h */
#ifndef TASK_COMM_LEN
#  define TASK_COMM_LEN 16
#else
static_assert(TASK_COMM_LEN == 16, "");
#endif

/* glibc does not provide clone() on ia64, only clone2(). Not only that, but it also doesn't provide a
 * prototype, only the symbol in the shared library (it provides a prototype for clone(), but not the
 * symbol in the shared library). */
#if defined(__ia64__)
int __clone2(int (*fn)(void *), void *stack_base, size_t stack_size, int flags, void *arg);
#define HAVE_CLONE 0
#else
/* We know that everywhere else clone() is available, so we don't bother with a meson check (that takes time
 * at build time) and just define it. Once the kernel drops ia64 support, we can drop this too. */
#define HAVE_CLONE 1
#endif

/* Defined since glibc-2.41.
 * Supported since kernel 3.14 (e6cfc0295c7d51b008999a8b13a44fb43f8685ea). */
#if !HAVE_SCHED_SETATTR
int missing_sched_setattr(pid_t pid, struct sched_attr *attr, unsigned flags);
#  define sched_setattr missing_sched_setattr
#endif
