/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "macro.h"
#include "rm-rf.h"

/* These functions implement various potentially slow operations that are executed asynchronously. They are
 * carefully written to not use pthreads, but use fork() or clone() (without CLONE_VM) so that the child does
 * not share any memory with the parent process, and thus cannot possibly interfere with the malloc()
 * synchronization locks.
 *
 * Background: glibc only synchronizes malloc() locks when doing fork(), but not when doing clone()
 * (regardless if through glibc's own wrapper or ours). This means if another thread in the parent has the
 * malloc() lock taken while a thread is cloning, the mutex will remain locked in the child (but the other
 * thread won't exist there), with no chance to ever be unlocked again. This will result in deadlocks. Hence
 * one has to make the choice: either never use threads in the parent, or never do memory allocation in the
 * child, or never use clone()/clone3() and stick to fork() only. Because we need clone()/clone3() we opted
 * for avoiding threads. */

int asynchronous_sync(pid_t *ret_pid);
int asynchronous_fsync(int fd, pid_t *ret_pid);
int asynchronous_close(int fd);
int asynchronous_rm_rf(const char *p, RemoveFlags flags);

DEFINE_TRIVIAL_CLEANUP_FUNC(int, asynchronous_close);
