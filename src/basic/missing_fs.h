/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

/* Not exposed yet. Defined at fs/fuse/inode.c */
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

/* Not exposed yet. Defined at fs/fuse/control.c */
#ifndef FUSE_CTL_SUPER_MAGIC
#define FUSE_CTL_SUPER_MAGIC 0x65735543
#endif

/* Not exposed yet. Defined at fs/ceph/super.h */
#ifndef CEPH_SUPER_MAGIC
#define CEPH_SUPER_MAGIC 0x00c36400
#endif

/* Not exposed yet. Defined at fs/orangefs/orangefs-kernel.h */
#ifndef ORANGEFS_DEVREQ_MAGIC
#define ORANGEFS_DEVREQ_MAGIC 0x20030529
#endif

/* linux/gfs2_ondisk.h */
#ifndef GFS2_MAGIC
#define GFS2_MAGIC 0x01161970
#endif

/* Not exposed yet. Defined at fs/configfs/mount.c */
#ifndef CONFIGFS_MAGIC
#define CONFIGFS_MAGIC 0x62656570
#endif

/* Not exposed yet. Defined at fs/vboxsf/super.c */
#ifndef VBOXSF_SUPER_MAGIC
#define VBOXSF_SUPER_MAGIC 0x786f4256
#endif

/* Not exposed yet. Defined at fs/exfat/exfat_fs.h */
#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC 0x2011BAB0UL
#endif
