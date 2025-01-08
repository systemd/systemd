/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/types.h>

#include "macro.h"

/* linux/fs.h */
#ifndef RENAME_NOREPLACE /* 0a7c3937a1f23f8cb5fc77ae01661e9968a51d0c (3.15) */
#define RENAME_NOREPLACE (1 << 0)
#endif

#ifndef BLKGETDISKSEQ /* 7957d93bf32bc211415827e44fdd9cdf1388df59 (5.15) */
#define BLKGETDISKSEQ _IOR(0x12,128,__u64)
#endif

#ifndef FICLONE /* 04b38d601239b4d9be641b412cf4b7456a041c67 (4.5) */
#define FICLONE _IOW(0x94, 9, int)
#endif

#ifndef FICLONERANGE /* 04b38d601239b4d9be641b412cf4b7456a041c67 (4.5) */
#define FICLONERANGE _IOW(0x94, 13, struct file_clone_range)
struct file_clone_range {
       __s64 src_fd;
       __u64 src_offset;
       __u64 src_length;
       __u64 dest_offset;
};
#endif

/* linux/fs.h or sys/mount.h */
#ifndef MS_MOVE
#  define MS_MOVE 8192
#else
assert_cc(MS_MOVE == 8192);
#endif

#ifndef MS_REC
#  define MS_REC 16384
#else
assert_cc(MS_REC == 16384);
#endif

#ifndef MS_PRIVATE
#  define MS_PRIVATE      (1<<18)
#else
assert_cc(MS_PRIVATE == (1<<18));
#endif

#ifndef MS_SLAVE
#  define MS_SLAVE        (1<<19)
#else
assert_cc(MS_SLAVE == (1<<19));
#endif

#ifndef MS_SHARED
#  define MS_SHARED       (1<<20)
#else
assert_cc(MS_SHARED == (1<<20));
#endif

#ifndef MS_RELATIME
#  define MS_RELATIME     (1<<21)
#else
assert_cc(MS_RELATIME == (1<<21));
#endif

#ifndef MS_KERNMOUNT
#  define MS_KERNMOUNT    (1<<22)
#else
assert_cc(MS_KERNMOUNT == (1<<22));
#endif

#ifndef MS_I_VERSION
#  define MS_I_VERSION    (1<<23)
#else
assert_cc(MS_I_VERSION == (1<<23));
#endif

#ifndef MS_STRICTATIME
#  define MS_STRICTATIME  (1<<24)
#else
assert_cc(MS_STRICTATIME == (1 << 24));
#endif

#ifndef MS_LAZYTIME
#  define MS_LAZYTIME     (1<<25)
#else
assert_cc(MS_LAZYTIME == (1<<25));
#endif

#ifndef FS_PROJINHERIT_FL
#  define FS_PROJINHERIT_FL 0x20000000
#else
assert_cc(FS_PROJINHERIT_FL == 0x20000000);
#endif

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* linux/fscrypt.h */
#ifndef FS_KEY_DESCRIPTOR_SIZE
#  define FS_KEY_DESCRIPTOR_SIZE 8
#else
assert_cc(FS_KEY_DESCRIPTOR_SIZE == 8);
#endif

/* linux/exportfs.h */
#ifndef FILEID_KERNFS
#define FILEID_KERNFS 0xfe
#endif
