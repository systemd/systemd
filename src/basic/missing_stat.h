/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/types.h>
#include <sys/stat.h>

#if WANT_LINUX_STAT_H
#include <linux/stat.h>
#endif

/* Thew newest definition we are aware of (fa2fcf4f1df1559a0a4ee0f46915b496cc2ebf60; 5.8) */
#define STATX_DEFINITION {                      \
        __u32 stx_mask;                         \
        __u32 stx_blksize;                      \
        __u64 stx_attributes;                   \
        __u32 stx_nlink;                        \
        __u32 stx_uid;                          \
        __u32 stx_gid;                          \
        __u16 stx_mode;                         \
        __u16 __spare0[1];                      \
        __u64 stx_ino;                          \
        __u64 stx_size;                         \
        __u64 stx_blocks;                       \
        __u64 stx_attributes_mask;              \
        struct statx_timestamp stx_atime;       \
        struct statx_timestamp stx_btime;       \
        struct statx_timestamp stx_ctime;       \
        struct statx_timestamp stx_mtime;       \
        __u32 stx_rdev_major;                   \
        __u32 stx_rdev_minor;                   \
        __u32 stx_dev_major;                    \
        __u32 stx_dev_minor;                    \
        __u64 stx_mnt_id;                       \
        __u64 __spare2;                         \
        __u64 __spare3[12];                     \
}

#if !HAVE_STRUCT_STATX
struct statx_timestamp {
        __s64 tv_sec;
        __u32 tv_nsec;
        __s32 __reserved;
};

struct statx STATX_DEFINITION;
#endif

/* Always define the newest version we are aware of as a distinct type, so that we can use it even if glibc
 * defines an older definition */
struct new_statx STATX_DEFINITION;

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef AT_STATX_SYNC_AS_STAT
#define AT_STATX_SYNC_AS_STAT 0x0000
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef AT_STATX_FORCE_SYNC
#define AT_STATX_FORCE_SYNC 0x2000
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_TYPE
#define STATX_TYPE 0x00000001U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_MODE
#define STATX_MODE 0x00000002U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_NLINK
#define STATX_NLINK 0x00000004U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_UID
#define STATX_UID 0x00000008U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_GID
#define STATX_GID 0x00000010U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_ATIME
#define STATX_ATIME 0x00000020U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_MTIME
#define STATX_MTIME 0x00000040U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_CTIME
#define STATX_CTIME 0x00000080U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_INO
#define STATX_INO 0x00000100U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_SIZE
#define STATX_SIZE 0x00000200U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_BLOCKS
#define STATX_BLOCKS 0x00000400U
#endif

/* a528d35e8bfcc521d7cb70aaf03e1bd296c8493f (4.11) */
#ifndef STATX_BTIME
#define STATX_BTIME 0x00000800U
#endif

/* fa2fcf4f1df1559a0a4ee0f46915b496cc2ebf60 (5.8) */
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

/* 80340fe3605c0e78cfe496c3b3878be828cfdbfe (5.8) */
#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT 0x00002000 /* Root of a mount */
#endif
