/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* since glibc-2.36 */
#if HAVE_PIDFD_OPEN
#include_next <sys/pidfd.h>     /* IWYU pragma: export */
#endif

#include <linux/types.h>
#include <signal.h>
#include <sys/ioctl.h>

/* Defined since glibc-2.36.
 * Supported since kernel v5.3 (7615d9e1780e26e0178c93c55b73309a5dc093d7). */
#if !HAVE_PIDFD_OPEN
int missing_pidfd_open(pid_t pid, unsigned flags);
#  define pidfd_open missing_pidfd_open
#endif

/* Defined since glibc-2.36.
 * Supported since kernel v5.1 (3eb39f47934f9d5a3027fe00d906a45fe3a15fad). */
#if !HAVE_PIDFD_SEND_SIGNAL
int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags);
#  define pidfd_send_signal missing_pidfd_send_signal
#endif

/* since glibc-2.41 */
#ifndef PIDFS_IOCTL_MAGIC
#  define PIDFS_IOCTL_MAGIC 0xFF

#  define PIDFD_GET_CGROUP_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 1)
#  define PIDFD_GET_IPC_NAMESPACE                 _IO(PIDFS_IOCTL_MAGIC, 2)
#  define PIDFD_GET_MNT_NAMESPACE                 _IO(PIDFS_IOCTL_MAGIC, 3)
#  define PIDFD_GET_NET_NAMESPACE                 _IO(PIDFS_IOCTL_MAGIC, 4)
#  define PIDFD_GET_PID_NAMESPACE                 _IO(PIDFS_IOCTL_MAGIC, 5)
#  define PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE    _IO(PIDFS_IOCTL_MAGIC, 6)
#  define PIDFD_GET_TIME_NAMESPACE                _IO(PIDFS_IOCTL_MAGIC, 7)
#  define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE   _IO(PIDFS_IOCTL_MAGIC, 8)
#  define PIDFD_GET_USER_NAMESPACE                _IO(PIDFS_IOCTL_MAGIC, 9)
#  define PIDFD_GET_UTS_NAMESPACE                 _IO(PIDFS_IOCTL_MAGIC, 10)
#endif

/* defined in linux/pidfd.h */
#ifndef PIDFD_GET_INFO

/* Flags for pidfd_info. */
#define PIDFD_INFO_PID                  (1UL << 0) /* Always returned, even if not requested */
#define PIDFD_INFO_CREDS                (1UL << 1) /* Always returned, even if not requested */
#define PIDFD_INFO_CGROUPID             (1UL << 2) /* Always returned if available, even if not requested */
#define PIDFD_INFO_EXIT                 (1UL << 3) /* Only returned if requested. */
#define PIDFD_INFO_COREDUMP             (1UL << 4) /* Only returned if requested. */

#define PIDFD_INFO_SIZE_VER0            64 /* sizeof first published struct */

/*
 * Values for @coredump_mask in pidfd_info.
 * Only valid if PIDFD_INFO_COREDUMP is set in @mask.
 *
 * Note, the @PIDFD_COREDUMP_ROOT flag indicates that the generated
 * coredump should be treated as sensitive and access should only be
 * granted to privileged users.
 */
#define PIDFD_COREDUMPED        (1U << 0) /* Did crash and... */
#define PIDFD_COREDUMP_SKIP     (1U << 1) /* coredumping generation was skipped. */
#define PIDFD_COREDUMP_USER     (1U << 2) /* coredump was done as the user. */
#define PIDFD_COREDUMP_ROOT     (1U << 3) /* coredump was done as root. */

struct pidfd_info {
        /*
         * This mask is similar to the request_mask in statx(2).
         *
         * Userspace indicates what extensions or expensive-to-calculate fields
         * they want by setting the corresponding bits in mask. The kernel
         * will ignore bits that it does not know about.
         *
         * When filling the structure, the kernel will only set bits
         * corresponding to the fields that were actually filled by the kernel.
         * This also includes any future extensions that might be automatically
         * filled. If the structure size is too small to contain a field
         * (requested or not), to avoid confusion the mask will not
         * contain a bit for that field.
         *
         * As such, userspace MUST verify that mask contains the
         * corresponding flags after the ioctl(2) returns to ensure that it is
         * using valid data.
         */
        __u64 mask;
        /*
         * The information contained in the following fields might be stale at the
         * time it is received, as the target process might have exited as soon as
         * the IOCTL was processed, and there is no way to avoid that. However, it
         * is guaranteed that if the call was successful, then the information was
         * correct and referred to the intended process at the time the work was
         * performed. */
        __u64 cgroupid;
        __u32 pid;
        __u32 tgid;
        __u32 ppid;
        __u32 ruid;
        __u32 rgid;
        __u32 euid;
        __u32 egid;
        __u32 suid;
        __u32 sgid;
        __u32 fsuid;
        __u32 fsgid;
        __s32 exit_code;     /* since kernel v6.15 (7477d7dce48a996ae4e4f0b5f7bd82de7ec9131b) */
        __u32 coredump_mask; /* since kernel v6.16 (1d8db6fd698de1f73b1a7d72aea578fdd18d9a87) */
        __u32 __spare1;
};

#define PIDFD_GET_INFO          _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
#endif /* PIDFD_GET_INFO */
