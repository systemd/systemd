/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <fcntl.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "missing.h"

int name_to_handle_at_loop(int fd, const char *path, struct file_handle **ret_handle, int *ret_mnt_id, int flags);

int path_get_mnt_id(const char *path, int *ret);

int fd_is_mount_point(int fd, const char *filename, int flags);
int path_is_mount_point(const char *path, const char *root, int flags);

int repeat_unmount(const char *path, int flags);

int umount_recursive(const char *target, int flags);
int bind_remount_recursive(const char *prefix, bool ro, char **blacklist);
int bind_remount_recursive_with_mountinfo(const char *prefix, bool ro, char **blacklist, FILE *proc_self_mountinfo);

int mount_move_root(const char *path);

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, endmntent);
#define _cleanup_endmntent_ _cleanup_(endmntentp)

bool fstype_is_network(const char *fstype);
bool fstype_is_api_vfs(const char *fstype);
bool fstype_is_ro(const char *fsype);
bool fstype_can_discard(const char *fstype);
bool fstype_can_uid_gid(const char *fstype);

const char* mode_to_inaccessible_node(mode_t mode);

int mount_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options);
int umount_verbose(const char *where);

const char *mount_propagation_flags_to_string(unsigned long flags);
int mount_propagation_flags_from_string(const char *name, unsigned long *ret);

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options);

int dev_is_devtmpfs(void);
