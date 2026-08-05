/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* We do not use linux/fcntl.h as it conflicts with glibc's fcntl.h. */
#include <fcntl.h>

/* The below are defined in linux/fcntl.h, but not defined in glibc's fcntl.h.
 * They are necessary for linux/pidfd.h, hence define them here. */

/*
 * The concept of process and threads in userland and the kernel is a confusing
 * one - within the kernel every thread is a 'task' with its own individual PID,
 * however from userland's point of view threads are grouped by a single PID,
 * which is that of the 'thread group leader', typically the first thread
 * spawned.
 *
 * To cut the Gideon knot, for internal kernel usage, we refer to
 * PIDFD_SELF_THREAD to refer to the current thread (or task from a kernel
 * perspective), and PIDFD_SELF_THREAD_GROUP to refer to the current thread
 * group leader...
 */
#define PIDFD_SELF_THREAD               -10000 /* Current thread. */
#define PIDFD_SELF_THREAD_GROUP         -10001 /* Current thread group leader. */
