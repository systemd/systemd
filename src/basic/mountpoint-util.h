/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The limit used for /dev itself. 4MB should be enough since device nodes and symlinks don't
 * consume any space and udev isn't supposed to create regular file either. There's no limit on the
 * max number of inodes since such limit is hard to guess especially on large storage array
 * systems. */
#define TMPFS_LIMITS_DEV             ",size=4m"

/* The limit used for /dev in private namespaces. 4MB for contents of regular files. The number of
 * inodes should be relatively low in private namespaces but for now use a 64k limit. */
#define TMPFS_LIMITS_PRIVATE_DEV     ",size=4m,nr_inodes=64k"

/* Very little, if any use expected */
#define TMPFS_LIMITS_EMPTY_OR_ALMOST ",size=4m,nr_inodes=1k"
#define TMPFS_LIMITS_SYS             TMPFS_LIMITS_EMPTY_OR_ALMOST

/* On an extremely small device with only 256MB of RAM, 20% of RAM should be enough for the re-execution of
 * PID1 because 16MB of free space is required. */
#define TMPFS_LIMITS_RUN             ",size=20%,nr_inodes=800k"

/* The limit used for various nested tmpfs mounts, in particular for guests started by systemd-nspawn.
 * 10% of RAM (using 16GB of RAM as a baseline) translates to 400k inodes (assuming 4k each) and 25%
 * translates to 1M inodes.
 * (On the host, /tmp is configured through a .mount unit file.) */
#define NESTED_TMPFS_LIMITS          ",size=10%,nr_inodes=400k"

/* More space for volatile root and /var */
#define TMPFS_LIMITS_VAR             ",size=25%,nr_inodes=1m"
#define TMPFS_LIMITS_ROOTFS          TMPFS_LIMITS_VAR
#define TMPFS_LIMITS_VOLATILE_STATE  TMPFS_LIMITS_VAR

bool is_name_to_handle_at_fatal_error(int err);

int name_to_handle_at_loop(int fd, const char *path, struct file_handle **ret_handle, int *ret_mnt_id, int flags);
int name_to_handle_at_try_fid(int fd, const char *path, struct file_handle **ret_handle, int *ret_mnt_id, int flags);

bool file_handle_equal(const struct file_handle *a, const struct file_handle *b);

int path_get_mnt_id_at(int dir_fd, const char *path, int *ret);
static inline int path_get_mnt_id(const char *path, int *ret) {
        return path_get_mnt_id_at(AT_FDCWD, path, ret);
}

int is_mount_point_at(int fd, const char *filename, int flags);
int path_is_mount_point_full(const char *path, const char *root, int flags);
static inline int path_is_mount_point(const char *path) {
        return path_is_mount_point_full(path, NULL, 0);
}

bool fstype_is_network(const char *fstype);
bool fstype_needs_quota(const char *fstype);
bool fstype_is_api_vfs(const char *fstype);
bool fstype_is_blockdev_backed(const char *fstype);
bool fstype_is_ro(const char *fsype);
bool fstype_can_discard(const char *fstype);
bool fstype_can_uid_gid(const char *fstype);
bool fstype_can_fmask_dmask(const char *fstype);

const char* fstype_norecovery_option(const char *fstype);

int dev_is_devtmpfs(void);

int mount_nofollow(
                const char *source,
                const char *target,
                const char *filesystemtype,
                unsigned long mountflags,
                const void *data);

const char* mount_propagation_flag_to_string(unsigned long flags);
int mount_propagation_flag_from_string(const char *name, unsigned long *ret);
bool mount_propagation_flag_is_valid(unsigned long flag);

bool mount_new_api_supported(void);
unsigned long ms_nosymfollow_supported(void);

int mount_option_supported(const char *fstype, const char *key, const char *value);

bool path_below_api_vfs(const char *p);
