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
