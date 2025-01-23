/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <mntent.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "macro.h"
#include "pidref.h"

typedef struct SubMount {
        char *path;
        int mount_fd;
} SubMount;

void sub_mount_array_free(SubMount *s, size_t n);

int get_sub_mounts(const char *prefix, SubMount **ret_mounts, size_t *ret_n_mounts);

int repeat_unmount(const char *path, int flags);

int umount_recursive_full(const char *target, int flags, char **keep);

static inline int umount_recursive(const char *target, int flags) {
        return umount_recursive_full(target, flags, NULL);
}

int bind_remount_recursive_with_mountinfo(const char *prefix, unsigned long new_flags, unsigned long flags_mask, char **deny_list, FILE *proc_self_mountinfo);
static inline int bind_remount_recursive(const char *prefix, unsigned long new_flags, unsigned long flags_mask, char **deny_list) {
        return bind_remount_recursive_with_mountinfo(prefix, new_flags, flags_mask, deny_list, NULL);
}

int bind_remount_one_with_mountinfo(const char *path, unsigned long new_flags, unsigned long flags_mask, FILE *proc_self_mountinfo);
int bind_remount_one(const char *path, unsigned long new_flags, unsigned long flags_mask);

int mount_switch_root_full(const char *path, unsigned long mount_propagation_flag, bool force_ms_move);
static inline int mount_switch_root(const char *path, unsigned long mount_propagation_flag) {
        return mount_switch_root_full(path, mount_propagation_flag, false);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, endmntent, NULL);
#define _cleanup_endmntent_ _cleanup_(endmntentp)

int mount_verbose_full(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options,
                bool follow_symlink);

static inline int mount_follow_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options) {
        return mount_verbose_full(error_log_level, what, where, type, flags, options, true);
}

static inline int mount_nofollow_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options) {
        return mount_verbose_full(error_log_level, what, where, type, flags, options, false);
}

int umount_verbose(
                int error_log_level,
                const char *where,
                int flags);

int umountat_detach_verbose(
                int error_log_level,
                int fd,
                const char *where);

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options);

int mode_to_inaccessible_node(const char *runtime_dir, mode_t mode, char **dest);
int mount_flags_to_string(unsigned long flags, char **ret);

/* Useful for usage with _cleanup_(), unmounts, removes a directory and frees the pointer */
static inline char* umount_and_rmdir_and_free(char *p) {
        if (!p)
                return NULL;

        PROTECT_ERRNO;
        (void) umount_recursive(p, 0);
        (void) rmdir(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, umount_and_rmdir_and_free);

static inline char* umount_and_free(char *p) {
        if (!p)
                return NULL;

        PROTECT_ERRNO;
        (void) umount_recursive(p, 0);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, umount_and_free);

char* umount_and_unlink_and_free(char *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, umount_and_unlink_and_free);

int mount_exchange_graceful(int fsmount_fd, const char *dest, bool mount_beneath);

typedef enum MountInNamespaceFlags {
        MOUNT_IN_NAMESPACE_READ_ONLY              = 1 << 0,
        MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY = 1 << 1,
        MOUNT_IN_NAMESPACE_IS_IMAGE               = 1 << 2,
} MountInNamespaceFlags;

int bind_mount_in_namespace(
                const PidRef *target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                MountInNamespaceFlags flags);
int mount_image_in_namespace(
                const PidRef *target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                const ImagePolicy *image_policy);

int make_mount_point(const char *path);
int fd_make_mount_point(int fd);

typedef enum RemountIdmapping {
        REMOUNT_IDMAPPING_NONE,
        /* Include a mapping from UID_MAPPED_ROOT (i.e. UID 2^31-2) on the backing fs to UID 0 on the
         * uidmapped fs. This is useful to ensure that the host root user can safely add inodes to the
         * uidmapped fs (which otherwise wouldn't work as the host root user is not defined on the uidmapped
         * mount and any attempts to create inodes will then be refused with EOVERFLOW). The idea is that
         * these inodes are quickly re-chown()ed to more suitable UIDs/GIDs. Any code that intends to be able
         * to add inodes to file systems mapped this way should set this flag, but given it comes with
         * certain security implications defaults to off, and requires explicit opt-in. */
        REMOUNT_IDMAPPING_HOST_ROOT,
        /* Much like REMOUNT_IDMAPPING_HOST_ROOT, but the source mapping is not from 0…65535 but from the
         * foreign UID range. */
        REMOUNT_IDMAPPING_FOREIGN_WITH_HOST_ROOT,
        /* Define a mapping from root user within the container to the owner of the bind mounted directory.
         * This ensures no root-owned files will be written in a bind-mounted directory owned by a different
         * user. No other users are mapped. */
        REMOUNT_IDMAPPING_HOST_OWNER,
        /* Define a mapping from bind-target owner within the container to the host owner of the bind mounted
         * directory. No other users are mapped. */
        REMOUNT_IDMAPPING_HOST_OWNER_TO_TARGET_OWNER,
        _REMOUNT_IDMAPPING_MAX,
        _REMOUNT_IDMAPPING_INVALID = -EINVAL,
} RemountIdmapping;

int make_userns(uid_t uid_shift, uid_t uid_range, uid_t host_owner, uid_t dest_owner, RemountIdmapping idmapping);
int remount_idmap_fd(char **p, int userns_fd, uint64_t extra_mount_attr_set);
int remount_idmap(char **p, uid_t uid_shift, uid_t uid_range, uid_t host_owner, uid_t dest_owner, RemountIdmapping idmapping);

int bind_mount_submounts(
                const char *source,
                const char *target);

/* Creates a mount point (not parents) based on the source path or stat - ie, a file or a directory */
int make_mount_point_inode_from_stat(const struct stat *st, const char *dest, mode_t mode);
int make_mount_point_inode_from_path(const char *source, const char *dest, mode_t mode);

int trigger_automount_at(int dir_fd, const char *path);

unsigned long credentials_fs_mount_flags(bool ro);
int mount_credentials_fs(const char *path, size_t size, bool ro);

int make_fsmount(int error_log_level, const char *what, const char *type, unsigned long flags, const char *options, int userns_fd);

int path_is_network_fs_harder_at(int dir_fd, const char *path);
static inline int path_is_network_fs_harder(const char *path) {
        return path_is_network_fs_harder_at(AT_FDCWD, path);
}
