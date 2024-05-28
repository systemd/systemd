/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/types.h>

#include "macro.h"

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* linux/nsfs.h */
#ifndef NS_GET_NSTYPE /* d95fa3c76a66b6d76b1e109ea505c55e66360f3c (4.11) */
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif

/* linux/exportfs.h */
#ifndef FILEID_KERNFS
#define FILEID_KERNFS 0xfe
#endif
