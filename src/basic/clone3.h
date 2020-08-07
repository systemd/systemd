/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/types.h>
#include <sched.h>
#include <unistd.h>

#if !HAVE_CLONE3

#include <sys/syscall.h>

#define CLONE_ARGS_DEFINITION {                 \
        __aligned_u64 flags;                    \
        __aligned_u64 pidfd;                    \
        __aligned_u64 child_tid;                \
        __aligned_u64 parent_tid;               \
        __aligned_u64 exit_signal;              \
        __aligned_u64 stack;                    \
        __aligned_u64 stack_size;               \
        __aligned_u64 tls;                      \
        __aligned_u64 set_tid;                  \
        __aligned_u64 set_tid_size;             \
        __aligned_u64 cgroup;                   \
}

struct clone_args CLONE_ARGS_DEFINITION;
struct new_clone_args CLONE_ARGS_DEFINITION;

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/* may be (invalid) negative number due to libseccomp, see PR 13319 */
#  if ! (defined __NR_clone3 && __NR_clone3 >= 0)
#    if defined __NR_clone3
#      undef __NR_clone3
#    endif
#    define __NR_clone3 435
#endif

static inline pid_t clone3(struct clone_args *args, size_t size) {
#ifdef __NR_clone3
        return syscall(__NR_clone3, args, size);
#else
        errno = ENOSYS;
        return -1;
#endif
}

#endif

pid_t fork_into_cgroup_fd(int cgroup_fd);
pid_t fork_into_cgroup_path(const char *path);
