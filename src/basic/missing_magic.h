/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/magic.h>

/* 62aa81d7c4c24b90fdb61da70ac0dbbc414f9939 (4.13) */
#ifndef OCFS2_SUPER_MAGIC
#define OCFS2_SUPER_MAGIC 0x7461636f
#endif

/* 67e9c74b8a873408c27ac9a8e4c1d1c8d72c93ff (4.5) */
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

/* 4282d60689d4f21b40692029080440cc58e8a17d (4.1) */
#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC 0x74726163
#endif

/* e149ed2b805fefdccf7ccdfc19eca22fdd4514ac (3.19) */
#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

/* b2197755b2633e164a439682fb05a9b5ea48f706 (4.4) */
#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

/* Not exposed yet (4.20). Defined at ipc/mqueue.c */
#ifndef MQUEUE_MAGIC
#define MQUEUE_MAGIC 0x19800202
#endif

/* Not exposed yet (as of Linux 5.4). Defined in fs/xfs/libxfs/xfs_format.h */
#ifndef XFS_SB_MAGIC
#define XFS_SB_MAGIC 0x58465342
#endif

/* Not exposed yet. Defined at fs/cifs/cifsglob.h */
#ifndef CIFS_MAGIC_NUMBER
#define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

/* 257f871993474e2bde6c497b54022c362cf398e1 (4.5) */
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

/* 2a28900be20640fcd1e548b1e3bad79e8221fcf9 (4.7) */
#ifndef UDF_SUPER_MAGIC
#define UDF_SUPER_MAGIC 0x15013346
#endif

/* b1123ea6d3b3da25af5c8a9d843bd07ab63213f4 (4.8)*/
#ifndef BALLOON_KVM_MAGIC
#define BALLOON_KVM_MAGIC 0x13661366
#endif

/* 48b4800a1c6af2cdda344ea4e2c843dcc1f6afc9 (4.8) */
#ifndef ZSMALLOC_MAGIC
#define ZSMALLOC_MAGIC 0x58295829
#endif

/* 3bc52c45bac26bf7ed1dc8d287ad1aeaed1250b6 (4.9) */
#ifndef DAXFS_MAGIC
#define DAXFS_MAGIC 0x64646178
#endif

/* 5ff193fbde20df5d80fec367cea3e7856c057320 (4.10) */
#ifndef RDTGROUP_SUPER_MAGIC
#define RDTGROUP_SUPER_MAGIC 0x7655821
#endif

/* a481f4d917835cad86701fc0d1e620c74bb5cd5f (4.13) */
#ifndef AAFS_MAGIC
#define AAFS_MAGIC 0x5a3c69f0
#endif

/* f044c8847bb61eff5e1e95b6f6bb950e7f4a73a4 (4.15) */
#ifndef AFS_FS_MAGIC
#define AFS_FS_MAGIC 0x6b414653
#endif

/* dddde68b8f06dd83486124b8d245e7bfb15c185d (4.20) */
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

/* 3ad20fe393b31025bebfc2d76964561f65df48aa (5.0) */
#ifndef BINDERFS_SUPER_MAGIC
#define BINDERFS_SUPER_MAGIC 0x6c6f6f70
#endif

/* ed63bb1d1f8469586006a9ca63c42344401aa2ab (5.3) */
#ifndef DMA_BUF_MAGIC
#define DMA_BUF_MAGIC 0x444d4142
#endif

/* ea8157ab2ae5e914dd427e5cfab533b6da3819cd (5.3) */
#ifndef Z3FOLD_MAGIC
#define Z3FOLD_MAGIC 0x33
#endif

/* 47e4937a4a7ca4184fd282791dfee76c6799966a (5.4) */
#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xe0f5e1e2
#endif

/* fe030c9b85e6783bc52fe86449c0a4b8aa16c753 (5.5) */
#ifndef PPC_CMM_MAGIC
#define PPC_CMM_MAGIC 0xc7571590
#endif

/* 8dcc1a9d90c10fa4143e5c17821082e5e60e46a1 (5.6) */
#ifndef ZONEFS_MAGIC
#define ZONEFS_MAGIC 0x5a4f4653
#endif

/* 3234ac664a870e6ea69ae3a57d824cd7edbeacc5 (5.8) */
#ifndef DEVMEM_MAGIC
#define DEVMEM_MAGIC 0x454d444d
#endif

/* Not in mainline but included in Ubuntu */
#ifndef SHIFTFS_MAGIC
#define SHIFTFS_MAGIC 0x6a656a62
#endif

/* 1507f51255c9ff07d75909a84e7c0d7f3c4b2f49 (5.14) */
#ifndef SECRETMEM_MAGIC
#define SECRETMEM_MAGIC 0x5345434d
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

/* Not exposed yet, internally actually called RPCAUTH_GSSMAGIC. Defined in net/sunrpc/rpc_pipe.c */
#ifndef RPC_PIPEFS_SUPER_MAGIC
#define RPC_PIPEFS_SUPER_MAGIC 0x67596969
#endif
