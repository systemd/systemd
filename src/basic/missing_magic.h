/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/magic.h>

/* Not exposed yet (4.20). Defined at ipc/mqueue.c */
#ifndef MQUEUE_MAGIC
#  define MQUEUE_MAGIC 0x19800202
#else
assert_cc(MQUEUE_MAGIC == 0x19800202);
#endif

/* b1123ea6d3b3da25af5c8a9d843bd07ab63213f4 (4.8), dropped by 68f2736a858324c3ec852f6c2cddd9d1c777357d (v6.0) */
#ifndef BALLOON_KVM_MAGIC
#  define BALLOON_KVM_MAGIC 0x13661366
#else
assert_cc(BALLOON_KVM_MAGIC == 0x13661366);
#endif

/* 48b4800a1c6af2cdda344ea4e2c843dcc1f6afc9 (4.8), dropped by 68f2736a858324c3ec852f6c2cddd9d1c777357d (v6.0) */
#ifndef ZSMALLOC_MAGIC
#  define ZSMALLOC_MAGIC 0x58295829
#else
assert_cc(ZSMALLOC_MAGIC == 0x58295829);
#endif

/* ea8157ab2ae5e914dd427e5cfab533b6da3819cd (5.3), dropped by 68f2736a858324c3ec852f6c2cddd9d1c777357d (v6.0) */
#ifndef Z3FOLD_MAGIC
#  define Z3FOLD_MAGIC 0x33
#else
assert_cc(Z3FOLD_MAGIC == 0x33);
#endif

/* fe030c9b85e6783bc52fe86449c0a4b8aa16c753 (5.5), dropped by 68f2736a858324c3ec852f6c2cddd9d1c777357d (v6.0) */
#ifndef PPC_CMM_MAGIC
#  define PPC_CMM_MAGIC 0xc7571590
#else
assert_cc(PPC_CMM_MAGIC == 0xc7571590);
#endif

/* Not in mainline but included in Ubuntu */
#ifndef SHIFTFS_MAGIC
#  define SHIFTFS_MAGIC 0x6a656a62
#else
assert_cc(SHIFTFS_MAGIC == 0x6a656a62);
#endif

/* Not exposed yet. Defined at fs/fuse/control.c */
#ifndef FUSE_CTL_SUPER_MAGIC
#  define FUSE_CTL_SUPER_MAGIC 0x65735543
#else
assert_cc(FUSE_CTL_SUPER_MAGIC == 0x65735543);
#endif

/* Not exposed yet. Defined at fs/orangefs/orangefs-kernel.h */
#ifndef ORANGEFS_DEVREQ_MAGIC
#  define ORANGEFS_DEVREQ_MAGIC 0x20030529
#else
assert_cc(ORANGEFS_DEVREQ_MAGIC == 0x20030529);
#endif

/* linux/gfs2_ondisk.h */
#ifndef GFS2_MAGIC
#  define GFS2_MAGIC 0x01161970
#else
assert_cc(GFS2_MAGIC == 0x01161970);
#endif

/* Not exposed yet. Defined at fs/configfs/mount.c */
#ifndef CONFIGFS_MAGIC
#  define CONFIGFS_MAGIC 0x62656570
#else
assert_cc(CONFIGFS_MAGIC == 0x62656570);
#endif

/* Not exposed yet. Defined at fs/vboxsf/super.c */
#ifndef VBOXSF_SUPER_MAGIC
#  define VBOXSF_SUPER_MAGIC 0x786f4256
#else
assert_cc(VBOXSF_SUPER_MAGIC == 0x786f4256);
#endif

/* Not exposed yet, internally actually called RPCAUTH_GSSMAGIC. Defined in net/sunrpc/rpc_pipe.c */
#ifndef RPC_PIPEFS_SUPER_MAGIC
#  define RPC_PIPEFS_SUPER_MAGIC 0x67596969
#else
assert_cc(RPC_PIPEFS_SUPER_MAGIC == 0x67596969);
#endif

/* Not exposed yet, defined at fs/ntfs/ntfs.h */
#ifndef NTFS_SB_MAGIC
#  define NTFS_SB_MAGIC 0x5346544e
#else
assert_cc(NTFS_SB_MAGIC == 0x5346544e);
#endif

/* Not exposed yet, encoded literally in fs/ntfs3/super.c. */
#ifndef NTFS3_SUPER_MAGIC
#  define NTFS3_SUPER_MAGIC 0x7366746e
#else
assert_cc(NTFS3_SUPER_MAGIC == 0x7366746e);
#endif
