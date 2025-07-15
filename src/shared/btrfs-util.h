/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "btrfs.h"      /* IWYU pragma: export */
#include "forward.h"

typedef struct BtrfsSubvolInfo {
        uint64_t subvol_id;
        usec_t otime; /* creation time */
        usec_t ctime; /* change time */

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
        BTRFS_SNAPSHOT_FALLBACK_COPY      = 1 << 0, /* If the source isn't a subvolume, reflink everything */
        BTRFS_SNAPSHOT_READ_ONLY          = 1 << 1,
        BTRFS_SNAPSHOT_RECURSIVE          = 1 << 2,
        BTRFS_SNAPSHOT_QUOTA              = 1 << 3,
        BTRFS_SNAPSHOT_FALLBACK_DIRECTORY = 1 << 4, /* If the destination doesn't support subvolumes, reflink/copy instead */
        BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE = 1 << 5, /* When we can't create a subvolume, use the FS_IMMUTABLE attribute for indicating read-only */
        BTRFS_SNAPSHOT_SIGINT             = 1 << 6, /* Check for SIGINT regularly, and return EINTR if seen */
        BTRFS_SNAPSHOT_SIGTERM            = 1 << 7, /* Ditto, but for SIGTERM */
        BTRFS_SNAPSHOT_LOCK_BSD           = 1 << 8, /* Return a BSD exclusively locked file descriptor referring to snapshot subvolume/directory. */
} BtrfsSnapshotFlags;

typedef enum BtrfsRemoveFlags {
        BTRFS_REMOVE_RECURSIVE = 1 << 0,
        BTRFS_REMOVE_QUOTA     = 1 << 1,
} BtrfsRemoveFlags;

int btrfs_is_subvol_at(int dir_fd, const char *path);
static inline int btrfs_is_subvol_fd(int fd) {
        return btrfs_is_subvol_at(fd, NULL);
}
static inline int btrfs_is_subvol(const char *path) {
        return btrfs_is_subvol_at(AT_FDCWD, path);
}

int btrfs_get_block_device_at(int dir_fd, const char *path, dev_t *ret);
static inline int btrfs_get_block_device(const char *path, dev_t *ret) {
        return btrfs_get_block_device_at(AT_FDCWD, path, ret);
}
static inline int btrfs_get_block_device_fd(int fd, dev_t *ret) {
        return btrfs_get_block_device_at(fd, "", ret);
}

int btrfs_defrag_fd(int fd);
int btrfs_defrag(const char *p);

int btrfs_quota_enable_fd(int fd, bool b);
int btrfs_quota_enable(const char *path, bool b);

int btrfs_quota_scan_start(int fd);
int btrfs_quota_scan_wait(int fd);
int btrfs_quota_scan_ongoing(int fd);

int btrfs_subvol_snapshot_at_full(int dir_fdf, const char *from, int dir_fdt, const char *to, BtrfsSnapshotFlags flags, copy_progress_path_t progress_path, copy_progress_bytes_t progress_bytes, void *userdata);
static inline int btrfs_subvol_snapshot_at(int dir_fdf, const char *from, int dir_fdt, const char *to, BtrfsSnapshotFlags flags) {
        return btrfs_subvol_snapshot_at_full(dir_fdf, from, dir_fdt, to, flags, NULL, NULL, NULL);
}

int btrfs_subvol_remove_at(int dir_fd, const char *path, BtrfsRemoveFlags flags);
static inline int btrfs_subvol_remove(const char *path, BtrfsRemoveFlags flags) {
        return btrfs_subvol_remove_at(AT_FDCWD, path, flags);
}

int btrfs_subvol_set_read_only_at(int dir_fd, const char *path, bool b);
static inline int btrfs_subvol_set_read_only_fd(int fd, bool b) {
        return btrfs_subvol_set_read_only_at(fd, NULL, b);
}
static inline int btrfs_subvol_set_read_only(const char *path, bool b) {
        return btrfs_subvol_set_read_only_at(AT_FDCWD, path, b);
}

int btrfs_subvol_get_read_only_fd(int fd);

int btrfs_subvol_get_id(int fd, const char *subvolume, uint64_t *ret);
int btrfs_subvol_get_id_fd(int fd, uint64_t *ret);
int btrfs_subvol_get_parent(int fd, uint64_t subvol_id, uint64_t *ret);

int btrfs_subvol_get_info_fd(int fd, uint64_t subvol_id, BtrfsSubvolInfo *info);

int btrfs_subvol_find_subtree_qgroup(int fd, uint64_t subvol_id, uint64_t *ret);

int btrfs_subvol_get_subtree_quota(const char *path, uint64_t subvol_id, BtrfsQuotaInfo *quota);
int btrfs_subvol_get_subtree_quota_fd(int fd, uint64_t subvol_id, BtrfsQuotaInfo *quota);

int btrfs_subvol_set_subtree_quota_limit(const char *path, uint64_t subvol_id, uint64_t referenced_max);
int btrfs_subvol_set_subtree_quota_limit_fd(int fd, uint64_t subvol_id, uint64_t referenced_max);

int btrfs_subvol_auto_qgroup_fd(int fd, uint64_t subvol_id, bool new_qgroup);
int btrfs_subvol_auto_qgroup(const char *path, uint64_t subvol_id, bool create_intermediary_qgroup);

int btrfs_subvol_make_default(const char *path);

int btrfs_qgroupid_make(uint64_t level, uint64_t id, uint64_t *ret);
int btrfs_qgroupid_split(uint64_t qgroupid, uint64_t *level, uint64_t *id);

int btrfs_qgroup_create(int fd, uint64_t qgroupid);
int btrfs_qgroup_destroy(int fd, uint64_t qgroupid);
int btrfs_qgroup_destroy_recursive(int fd, uint64_t qgroupid);

int btrfs_qgroup_set_limit_fd(int fd, uint64_t qgroupid, uint64_t referenced_max);
int btrfs_qgroup_set_limit(const char *path, uint64_t qgroupid, uint64_t referenced_max);

int btrfs_qgroup_copy_limits(int fd, uint64_t old_qgroupid, uint64_t new_qgroupid);

int btrfs_qgroup_assign(int fd, uint64_t child, uint64_t parent);
int btrfs_qgroup_unassign(int fd, uint64_t child, uint64_t parent);

int btrfs_qgroup_find_parents(int fd, uint64_t qgroupid, uint64_t **ret);

int btrfs_qgroup_get_quota_fd(int fd, uint64_t qgroupid, BtrfsQuotaInfo *quota);
int btrfs_qgroup_get_quota(const char *path, uint64_t qgroupid, BtrfsQuotaInfo *quota);

int btrfs_log_dev_root(int level, int ret, const char *p);

bool btrfs_might_be_subvol(const struct stat *st) _pure_;

int btrfs_forget_device(const char *path);

int btrfs_get_file_physical_offset_fd(int fd, uint64_t *ret);
