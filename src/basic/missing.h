/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/falloc.h>
#include <linux/oom.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <uchar.h>
#include <unistd.h>

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#if HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#else
#define VMADDR_CID_ANY -1U
struct sockaddr_vm {
        unsigned short svm_family;
        unsigned short svm_reserved1;
        unsigned int svm_port;
        unsigned int svm_cid;
        unsigned char svm_zero[sizeof(struct sockaddr) -
                               sizeof(unsigned short) -
                               sizeof(unsigned short) -
                               sizeof(unsigned int) -
                               sizeof(unsigned int)];
};
#endif /* !HAVE_LINUX_VM_SOCKETS_H */

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

/* If RLIMIT_RTTIME is not defined, then we cannot use RLIMIT_NLIMITS as is */
#define _RLIMIT_MAX (RLIMIT_RTTIME+1 > RLIMIT_NLIMITS ? RLIMIT_RTTIME+1 : RLIMIT_NLIMITS)

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef OOM_SCORE_ADJ_MIN
#define OOM_SCORE_ADJ_MIN (-1000)
#endif

#ifndef OOM_SCORE_ADJ_MAX
#define OOM_SCORE_ADJ_MAX 1000
#endif

#ifndef AUDIT_SERVICE_START
#define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#endif

#ifndef AUDIT_SERVICE_STOP
#define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#endif

#ifndef TIOCVHANGUP
#define TIOCVHANGUP 0x5437
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_LIST_MEMBERSHIPS
#define NETLINK_LIST_MEMBERSHIPS 9
#endif

#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif

#ifndef FS_NOCOW_FL
#define FS_NOCOW_FL 0x00800000
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#ifndef MS_MOVE
#define MS_MOVE 8192
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE      (1<<18)
#endif

#ifndef MS_REC
#define MS_REC          (1<<19)
#endif

#ifndef MS_SHARED
#define MS_SHARED       (1<<20)
#endif

#ifndef MS_RELATIME
#define MS_RELATIME     (1<<21)
#endif

#ifndef MS_KERNMOUNT
#define MS_KERNMOUNT    (1<<22)
#endif

#ifndef MS_I_VERSION
#define MS_I_VERSION    (1<<23)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1<<24)
#endif

#ifndef MS_LAZYTIME
#define MS_LAZYTIME     (1<<25)
#endif

#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

#ifndef DM_DEFERRED_REMOVE
#define DM_DEFERRED_REMOVE (1 << 17)
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#if ! HAVE_SECURE_GETENV
#  if HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    error "neither secure_getenv nor __secure_getenv are available"
#  endif
#endif

#ifndef CIFS_MAGIC_NUMBER
#  define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

#ifndef TFD_TIMER_CANCEL_ON_SET
#  define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

#ifndef SO_REUSEPORT
#  define SO_REUSEPORT 15
#endif

#ifndef SO_PEERGROUPS
#  define SO_PEERGROUPS 59
#endif

#ifndef DRM_IOCTL_SET_MASTER
#  define DRM_IOCTL_SET_MASTER _IO('d', 0x1e)
#endif

#ifndef DRM_IOCTL_DROP_MASTER
#  define DRM_IOCTL_DROP_MASTER _IO('d', 0x1f)
#endif

/* The precise definition of __O_TMPFILE is arch specific; use the
 * values defined by the kernel (note: some are hexa, some are octal,
 * duplicated as-is from the kernel definitions):
 * - alpha, parisc, sparc: each has a specific value;
 * - others: they use the "generic" value.
 */

#ifndef __O_TMPFILE
#if defined(__alpha__)
#define __O_TMPFILE     0100000000
#elif defined(__parisc__) || defined(__hppa__)
#define __O_TMPFILE     0400000000
#elif defined(__sparc__) || defined(__sparc64__)
#define __O_TMPFILE     0x2000000
#else
#define __O_TMPFILE     020000000
#endif
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

/* Note that LOOPBACK_IFINDEX is currently not exported by the
 * kernel/glibc, but hardcoded internally by the kernel.  However, as
 * it is exported to userspace indirectly via rtnetlink and the
 * ioctls, and made use of widely we define it here too, in a way that
 * is compatible with the kernel's internal definition. */
#ifndef LOOPBACK_IFINDEX
#define LOOPBACK_IFINDEX 1
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#define MAX_AUDIT_MESSAGE_LENGTH 8970
#endif

#ifndef AUDIT_NLGRP_MAX
#define AUDIT_NLGRP_READLOG 1
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE 32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN 33
#endif

#ifndef CAP_SYSLOG
#define CAP_SYSLOG 34
#endif

#ifndef CAP_WAKE_ALARM
#define CAP_WAKE_ALARM 35
#endif

#ifndef CAP_BLOCK_SUSPEND
#define CAP_BLOCK_SUSPEND 36
#endif

#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ 37
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

#ifndef KCMP_FILE
#define KCMP_FILE 0
#endif

#if !HAVE_CHAR32_T
#define char32_t uint32_t
#endif

#if !HAVE_CHAR16_T
#define char16_t uint16_t
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef EXT4_IOC_RESIZE_FS
#  define EXT4_IOC_RESIZE_FS              _IOW('f', 16, __u64)
#endif

#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

/* The maximum thread/process name length including trailing NUL byte. This mimics the kernel definition of the same
 * name, which we need in userspace at various places but is not defined in userspace currently, neither under this
 * name nor any other. */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#include "missing_btrfs_tree.h"
#include "missing_input.h"
#include "missing_magic.h"
#include "missing_network.h"
#include "missing_prctl.h"

#include "missing_syscall.h"
