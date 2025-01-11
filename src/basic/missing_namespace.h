/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/types.h>

/* Root namespace inode numbers, as per include/linux/proc_ns.h in the kernel source tree, since v3.8:
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=98f842e675f96ffac96e6c50315790912b2812be */

#define PROC_IPC_INIT_INO    ((ino_t) UINT32_C(0xEFFFFFFF))
#define PROC_UTS_INIT_INO    ((ino_t) UINT32_C(0xEFFFFFFE))
#define PROC_USER_INIT_INO   ((ino_t) UINT32_C(0xEFFFFFFD))
#define PROC_PID_INIT_INO    ((ino_t) UINT32_C(0xEFFFFFFC))
#define PROC_CGROUP_INIT_INO ((ino_t) UINT32_C(0xEFFFFFFB))
#define PROC_TIME_INIT_INO   ((ino_t) UINT32_C(0xEFFFFFFA))

/* linux/nsfs.h */
#ifndef NS_GET_USERNS /* 6786741dbf99e44fb0c0ed85a37582b8a26f1c3b (4.9) */
#define NS_GET_USERNS _IO(0xb7, 0x1)
#endif

#ifndef NS_GET_NSTYPE /* e5ff5ce6e20ee22511398bb31fb912466cf82a36 (4.11) */
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif

#ifndef NS_GET_OWNER_UID /* d95fa3c76a66b6d76b1e109ea505c55e66360f3c (4.11) */
#define NS_GET_OWNER_UID _IO(0xb7, 0x4)
#endif
