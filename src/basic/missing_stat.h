/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/types.h>
#include <sys/stat.h>

#if WANT_LINUX_STAT_H
#include <linux/stat.h>
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#if !HAVE_STRUCT_STATX
struct statx_timestamp {
        int64_t tv_sec;
        uint32_t tv_nsec;
        uint32_t __reserved;
};
struct statx {
        uint32_t stx_mask;
        uint32_t stx_blksize;
        uint64_t stx_attributes;
        uint32_t stx_nlink;
        uint32_t stx_uid;
        uint32_t stx_gid;
        uint16_t stx_mode;
        uint16_t __spare0[1];
        uint64_t stx_ino;
        uint64_t stx_size;
        uint64_t stx_blocks;
        uint64_t stx_attributes_mask;
        struct statx_timestamp stx_atime;
        struct statx_timestamp stx_btime;
        struct statx_timestamp stx_ctime;
        struct statx_timestamp stx_mtime;
        uint32_t stx_rdev_major;
        uint32_t stx_rdev_minor;
        uint32_t stx_dev_major;
        uint32_t stx_dev_minor;
        uint64_t __spare2[14];
};
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_BTIME
#define STATX_BTIME 0x00000800U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif
