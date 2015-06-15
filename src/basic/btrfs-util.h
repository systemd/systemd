/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "time-util.h"

typedef struct BtrfsSubvolInfo {
        uint64_t subvol_id;
        usec_t otime;

        sd_id128_t uuid;
        sd_id128_t parent_uuid;

        bool read_only;
} BtrfsSubvolInfo;

typedef struct BtrfsQuotaInfo {
        uint64_t referenced;
        uint64_t exclusive;
        uint64_t referenced_max;
        uint64_t exclusive_max;
} BtrfsQuotaInfo;

typedef enum BtrfsSnapshotFlags {
        BTRFS_SNAPSHOT_FALLBACK_COPY = 1,
        BTRFS_SNAPSHOT_READ_ONLY = 2,
        BTRFS_SNAPSHOT_RECURSIVE = 4,
} BtrfsSnapshotFlags;

int btrfs_is_filesystem(int fd);
int btrfs_is_subvol(int fd);

int btrfs_subvol_make(const char *path);
int btrfs_subvol_make_label(const char *path);

int btrfs_subvol_snapshot_fd(int old_fd, const char *new_path, BtrfsSnapshotFlags flags);
int btrfs_subvol_snapshot(const char *old_path, const char *new_path, BtrfsSnapshotFlags flags);

int btrfs_subvol_set_read_only_fd(int fd, bool b);
int btrfs_subvol_set_read_only(const char *path, bool b);
int btrfs_subvol_get_read_only_fd(int fd);
int btrfs_subvol_get_id(int fd, const char *subvolume, uint64_t *ret);
int btrfs_subvol_get_id_fd(int fd, uint64_t *ret);
int btrfs_subvol_get_info_fd(int fd, BtrfsSubvolInfo *info);
int btrfs_subvol_get_quota_fd(int fd, BtrfsQuotaInfo *quota);

int btrfs_reflink(int infd, int outfd);
int btrfs_clone_range(int infd, uint64_t in_offset, int ofd, uint64_t out_offset, uint64_t sz);

int btrfs_get_block_device_fd(int fd, dev_t *dev);
int btrfs_get_block_device(const char *path, dev_t *dev);

int btrfs_defrag_fd(int fd);
int btrfs_defrag(const char *p);

int btrfs_quota_enable_fd(int fd, bool b);
int btrfs_quota_enable(const char *path, bool b);

int btrfs_quota_limit_fd(int fd, uint64_t referenced_max);
int btrfs_quota_limit(const char *path, uint64_t referenced_max);

int btrfs_resize_loopback_fd(int fd, uint64_t size, bool grow_only);
int btrfs_resize_loopback(const char *path, uint64_t size, bool grow_only);

int btrfs_subvol_remove(const char *path, bool recursive);
int btrfs_subvol_remove_fd(int fd, const char *subvolume, bool recursive);
