/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "pidref.h"

/* Much like PidRef references a process, ThreadRef references a specific thread of a process. It combines a
 * PidRef pinning the process with the kernel thread ID of the thread and a pidfd for the thread itself,
 * allocated with PIDFD_THREAD. The latter is only available on kernels 6.9+; on older kernels
 * thread_pidfd is set to -EBADF. Like PidRef's fd_id, thread_pidfd_id is the inode number of the thread
 * pidfd, which is acquired lazily, see threadref_acquire_pidfd_id(). */
typedef struct ThreadRef {
        PidRef process;
        pid_t thread_id;
        int thread_pidfd;
        uint64_t thread_pidfd_id;
} ThreadRef;

#define THREADREF_NULL (ThreadRef) { .process = PIDREF_NULL, .thread_pidfd = -EBADF }

static inline bool threadref_is_set(const ThreadRef *t) {
        return t && pidref_is_set(&t->process) && t->thread_id > 0;
}

/* Initializes a ThreadRef for the specified thread of the specified process. If tid is zero the main thread
 * is referenced. Returns -ESRCH if the process is gone, and -ENXIO if the thread does not exist or is not
 * part of the process. If pidfd_id is non-zero, it is additionally checked that the thread pidfd has that
 * inode number (if thread pidfds are supported), i.e. that the TID refers to the expected thread, and
 * -ENXIO returned if not. */
int threadref_set_full(ThreadRef *t, const PidRef *process, pid_t tid, uint64_t pidfd_id);
static inline int threadref_set(ThreadRef *t, const PidRef *process, pid_t tid) {
        return threadref_set_full(t, process, tid, /* pidfd_id= */ 0);
}

/* Acquires the inode number of the thread pidfd, if not acquired yet. Returns -ENOMEDIUM if there's no thread
 * pidfd, i.e. on kernels older than 6.9. */
int threadref_acquire_pidfd_id(ThreadRef *t);

void threadref_done(ThreadRef *t);
int threadref_copy(const ThreadRef *t, ThreadRef *ret);

/* Checks whether both ThreadRefs reference the same thread. Like pidref_equal() this compares the pidfd inode
 * numbers if available, i.e. on kernels that support thread pidfds (6.9+). On older kernels only the PID and
 * TID are compared, hence a recycled TID cannot be detected. */
bool threadref_equal(ThreadRef *a, ThreadRef *b);

#define TAKE_THREADREF(t) TAKE_GENERIC((t), ThreadRef, THREADREF_NULL)

/* Checks that the thread still exists, is still part of the process, and that neither the PID nor the TID
 * have been recycled. Returns -ESRCH if the process is gone, -ENXIO if the thread is gone. Should be called
 * after reading information about the thread from procfs. */
int threadref_verify(const ThreadRef *t);

/* Reads the name (i.e. the comm field) of the thread, and verifies the result via threadref_verify() */
int threadref_get_comm(const ThreadRef *t, char **ret);
