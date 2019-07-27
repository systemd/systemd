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
        __s64 tv_sec;
        __u32 tv_nsec;
        __s32 __reserved;
};
struct statx {
        __u32 stx_mask;
        __u32 stx_blksize;
        __u64 stx_attributes;
        __u32 stx_nlink;
        __u32 stx_uid;
        __u32 stx_gid;
        __u16 stx_mode;
        __u16 __spare0[1];
        __u64 stx_ino;
        __u64 stx_size;
        __u64 stx_blocks;
        __u64 stx_attributes_mask;
        struct statx_timestamp stx_atime;
        struct statx_timestamp stx_btime;
        struct statx_timestamp stx_ctime;
        struct statx_timestamp stx_mtime;
        __u32 stx_rdev_major;
        __u32 stx_rdev_minor;
        __u32 stx_dev_major;
        __u32 stx_dev_minor;
        __u64 __spare2[14];
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
