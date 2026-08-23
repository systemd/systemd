/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <linux/fs.h>      /* IWYU pragma: export */

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* linux/exportfs.h (33c5ac9175195c36a0b7005aaf503a2e81f117a1, 5.5) */
#ifndef FILEID_KERNFS
#define FILEID_KERNFS 0xfe
#endif
