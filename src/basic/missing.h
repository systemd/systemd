/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <inttypes.h>
#include <linux/falloc.h>
#include <stdlib.h>
#include <sys/syscall.h>

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef TIOCVHANGUP
#define TIOCVHANGUP 0x5437
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

#ifndef DM_DEFERRED_REMOVE
#define DM_DEFERRED_REMOVE (1 << 17)
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

#ifndef DRM_IOCTL_SET_MASTER
#  define DRM_IOCTL_SET_MASTER _IO('d', 0x1e)
#endif

#ifndef DRM_IOCTL_DROP_MASTER
#  define DRM_IOCTL_DROP_MASTER _IO('d', 0x1f)
#endif

#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
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

#include "missing_audit.h"
#include "missing_btrfs_tree.h"
#include "missing_capability.h"
#include "missing_fcntl.h"
#include "missing_input.h"
#include "missing_magic.h"
#include "missing_network.h"
#include "missing_prctl.h"
#include "missing_resource.h"
#include "missing_socket.h"
#include "missing_timerfd.h"
#include "missing_type.h"

#include "missing_syscall.h"
