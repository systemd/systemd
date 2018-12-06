/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <inttypes.h>
#include <sys/syscall.h>

#ifndef FS_NOCOW_FL
#define FS_NOCOW_FL 0x00800000
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

#ifndef CIFS_MAGIC_NUMBER
#  define CIFS_MAGIC_NUMBER 0xFF534D42
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

#include "missing_audit.h"
#include "missing_btrfs_tree.h"
#include "missing_capability.h"
#include "missing_fcntl.h"
#include "missing_input.h"
#include "missing_magic.h"
#include "missing_mman.h"
#include "missing_network.h"
#include "missing_prctl.h"
#include "missing_random.h"
#include "missing_resource.h"
#include "missing_sched.h"
#include "missing_socket.h"
#include "missing_stdlib.h"
#include "missing_timerfd.h"
#include "missing_type.h"

#include "missing_syscall.h"
