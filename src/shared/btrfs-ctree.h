/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

#include "sparse-endian.h"

/* Stolen from btrfs' ctree.h */

struct btrfs_timespec {
        le64_t sec;
        le32_t nsec;
} _packed_;

struct btrfs_disk_key {
        le64_t objectid;
        uint8_t type;
        le64_t offset;
} _packed_;

struct btrfs_inode_item {
        le64_t generation;
        le64_t transid;
        le64_t size;
        le64_t nbytes;
        le64_t block_group;
        le32_t nlink;
        le32_t uid;
        le32_t gid;
        le32_t mode;
        le64_t rdev;
        le64_t flags;
        le64_t sequence;
        le64_t reserved[4];
        struct btrfs_timespec atime;
        struct btrfs_timespec ctime;
        struct btrfs_timespec mtime;
        struct btrfs_timespec otime;
} _packed_;

struct btrfs_root_item {
        struct btrfs_inode_item inode;
        le64_t generation;
        le64_t root_dirid;
        le64_t bytenr;
        le64_t byte_limit;
        le64_t bytes_used;
        le64_t last_snapshot;
        le64_t flags;
        le32_t refs;
        struct btrfs_disk_key drop_progress;
        uint8_t drop_level;
        uint8_t level;
        le64_t generation_v2;
        uint8_t uuid[BTRFS_UUID_SIZE];
        uint8_t parent_uuid[BTRFS_UUID_SIZE];
        uint8_t received_uuid[BTRFS_UUID_SIZE];
        le64_t ctransid;
        le64_t otransid;
        le64_t stransid;
        le64_t rtransid;
        struct btrfs_timespec ctime;
        struct btrfs_timespec otime;
        struct btrfs_timespec stime;
        struct btrfs_timespec rtime;
        le64_t reserved[8];
} _packed_;

#define BTRFS_ROOT_SUBVOL_RDONLY (1ULL << 0)
