/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* since glibc-2.36 */
#if HAVE_PIDFD_OPEN
#include_next <sys/pidfd.h>
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
struct pidfd_info {
        __u64 mask;
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
        __u32 spare0[1];
};

#define PIDFD_GET_INFO          _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
#define PIDFD_INFO_PID          (1UL << 0)
#define PIDFD_INFO_CREDS        (1UL << 1)
#define PIDFD_INFO_CGROUPID     (1UL << 2)
#endif
