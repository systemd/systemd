/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* linux/fs.h */
#ifndef RENAME_NOREPLACE /* 0a7c3937a1f23f8cb5fc77ae01661e9968a51d0c (3.15) */
#define RENAME_NOREPLACE (1 << 0)
#endif

/* linux/fs.h or sys/mount.h */
#ifndef MS_MOVE
#define MS_MOVE 8192
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE      (1<<18)
#endif

#ifndef MS_SLAVE
#define MS_SLAVE        (1<<19)
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

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* Not exposed yet. Defined at fs/cifs/cifsglob.h */
#ifndef CIFS_MAGIC_NUMBER
#define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

/* linux/nsfs.h */
#ifndef NS_GET_NSTYPE /* d95fa3c76a66b6d76b1e109ea505c55e66360f3c (4.11) */
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif

#ifndef FS_PROJINHERIT_FL
#define FS_PROJINHERIT_FL 0x20000000
#endif
