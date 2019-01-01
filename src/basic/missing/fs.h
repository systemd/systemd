/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/fs.h>

#ifndef RENAME_NOREPLACE /* 0a7c3937a1f23f8cb5fc77ae01661e9968a51d0c (3.15) */
#define RENAME_NOREPLACE (1 << 0)
#endif

#ifndef MS_LAZYTIME /* 0ae45f63d4ef8d8eeec49c7d8b44a1775fff13e8 (4.0) */
#define MS_LAZYTIME     (1<<25)
#endif

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* linux/nsfs.h */
#ifndef NS_GET_NSTYPE /* d95fa3c76a66b6d76b1e109ea505c55e66360f3c (4.11) */
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif
