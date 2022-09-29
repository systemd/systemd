/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>

int name_to_handle_at_loop(int fd, const char *path, struct file_handle **ret_handle, int *ret_mnt_id, int flags);

int path_get_mnt_id(const char *path, int *ret);

int fd_is_mount_point(int fd, const char *filename, int flags);
int path_is_mount_point(const char *path, const char *root, int flags);

bool fstype_is_network(const char *fstype);
bool fstype_needs_quota(const char *fstype);
bool fstype_is_api_vfs(const char *fstype);
bool fstype_is_blockdev_backed(const char *fstype);
bool fstype_is_ro(const char *fsype);
bool fstype_can_discard(const char *fstype);
bool fstype_can_uid_gid(const char *fstype);

int dev_is_devtmpfs(void);

const char *mount_propagation_flags_to_string(unsigned long flags);
int mount_propagation_flags_from_string(const char *name, unsigned long *ret);
