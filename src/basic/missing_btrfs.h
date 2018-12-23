/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* Old btrfs.h requires stddef.h to be included before btrfs.h */
#include <stddef.h>

#include <linux/btrfs.h>

/* linux@57254b6ebce4ceca02d9c8b615f6059c56c19238 (3.11) */
#ifndef BTRFS_IOC_QUOTA_RESCAN_WAIT
#define BTRFS_IOC_QUOTA_RESCAN_WAIT _IO(BTRFS_IOCTL_MAGIC, 46)
#endif

/* linux@83288b60bf6668933689078973136e0c9d387b38 (4.7) */
#ifndef BTRFS_QGROUP_LIMIT_MAX_RFER
#define BTRFS_QGROUP_LIMIT_MAX_RFER (1ULL << 0)
#define BTRFS_QGROUP_LIMIT_MAX_EXCL (1ULL << 1)
#define BTRFS_QGROUP_LIMIT_RSV_RFER (1ULL << 2)
#define BTRFS_QGROUP_LIMIT_RSV_EXCL (1ULL << 3)
#define BTRFS_QGROUP_LIMIT_RFER_CMPR (1ULL << 4)
#define BTRFS_QGROUP_LIMIT_EXCL_CMPR (1ULL << 5)
#endif
