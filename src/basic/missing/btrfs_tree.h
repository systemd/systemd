/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/types.h>

#include "missing/btrfs.h"

/* linux@db6711600e27c885aed89751f04e727f3af26715 (4.7) */
#if HAVE_LINUX_BTRFS_TREE_H
#include <linux/btrfs_tree.h>
#else
#define BTRFS_ROOT_TREE_OBJECTID  1
#define BTRFS_QUOTA_TREE_OBJECTID 8
#define BTRFS_FIRST_FREE_OBJECTID 256
#define BTRFS_LAST_FREE_OBJECTID -256ULL

#define BTRFS_ROOT_ITEM_KEY       132
#define BTRFS_ROOT_BACKREF_KEY    144
#define BTRFS_QGROUP_STATUS_KEY   240
#define BTRFS_QGROUP_INFO_KEY     242
#define BTRFS_QGROUP_LIMIT_KEY    244
#define BTRFS_QGROUP_RELATION_KEY 246

struct btrfs_disk_key {
        __le64 objectid;
        __u8 type;
        __le64 offset;
} __attribute__ ((__packed__));

struct btrfs_timespec {
        __le64 sec;
        __le32 nsec;
} __attribute__ ((__packed__));

struct btrfs_inode_item {
        __le64 generation;
        __le64 transid;
        __le64 size;
        __le64 nbytes;
        __le64 block_group;
        __le32 nlink;
        __le32 uid;
        __le32 gid;
        __le32 mode;
        __le64 rdev;
        __le64 flags;
        __le64 sequence;
        __le64 reserved[4];
        struct btrfs_timespec atime;
        struct btrfs_timespec ctime;
        struct btrfs_timespec mtime;
        struct btrfs_timespec otime;
} __attribute__ ((__packed__));

#define BTRFS_ROOT_SUBVOL_RDONLY (1ULL << 0)

struct btrfs_root_item {
        struct btrfs_inode_item inode;
        __le64 generation;
        __le64 root_dirid;
        __le64 bytenr;
        __le64 byte_limit;
        __le64 bytes_used;
        __le64 last_snapshot;
        __le64 flags;
        __le32 refs;
        struct btrfs_disk_key drop_progress;
        __u8 drop_level;
        __u8 level;

        __le64 generation_v2;
        __u8 uuid[BTRFS_UUID_SIZE];
        __u8 parent_uuid[BTRFS_UUID_SIZE];
        __u8 received_uuid[BTRFS_UUID_SIZE];
        __le64 ctransid; /* updated when an inode changes */
        __le64 otransid; /* trans when created */
        __le64 stransid; /* trans when sent. non-zero for received subvol */
        __le64 rtransid; /* trans when received. non-zero for received subvol */
        struct btrfs_timespec ctime;
        struct btrfs_timespec otime;
        struct btrfs_timespec stime;
        struct btrfs_timespec rtime;
        __le64 reserved[8]; /* for future */
} __attribute__ ((__packed__));

struct btrfs_root_ref {
        __le64 dirid;
        __le64 sequence;
        __le16 name_len;
} __attribute__ ((__packed__));

#define BTRFS_QGROUP_LEVEL_SHIFT  48

struct btrfs_qgroup_info_item {
        __le64 generation;
        __le64 rfer;
        __le64 rfer_cmpr;
        __le64 excl;
        __le64 excl_cmpr;
} __attribute__ ((__packed__));

struct btrfs_qgroup_limit_item {
        __le64 flags;
        __le64 max_rfer;
        __le64 max_excl;
        __le64 rsv_rfer;
        __le64 rsv_excl;
} __attribute__ ((__packed__));
#endif
