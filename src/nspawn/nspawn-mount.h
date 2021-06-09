/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "cgroup-util.h"
#include "volatile-util.h"

typedef enum MountSettingsMask {
        MOUNT_FATAL              = 1 << 0, /* if set, a mount error is considered fatal */
        MOUNT_USE_USERNS         = 1 << 1, /* if set, mounts are patched considering uid/gid shifts in a user namespace */
        MOUNT_IN_USERNS          = 1 << 2, /* if set, the mount is executed in the inner child, otherwise in the outer child */
        MOUNT_APPLY_APIVFS_RO    = 1 << 3, /* if set, /proc/sys, and /sys will be mounted read-only, otherwise read-write. */
        MOUNT_APPLY_APIVFS_NETNS = 1 << 4, /* if set, /proc/sys/net will be mounted read-write.
                                               Works only if MOUNT_APPLY_APIVFS_RO is also set. */
        MOUNT_APPLY_TMPFS_TMP    = 1 << 5, /* if set, /tmp will be mounted as tmpfs */
        MOUNT_ROOT_ONLY          = 1 << 6, /* if set, only root mounts are mounted */
        MOUNT_NON_ROOT_ONLY      = 1 << 7, /* if set, only non-root mounts are mounted */
        MOUNT_MKDIR              = 1 << 8, /* if set, make directory to mount over first */
        MOUNT_TOUCH              = 1 << 9, /* if set, touch file to mount over first */
        MOUNT_PREFIX_ROOT        = 1 << 10,/* if set, prefix the source path with the container's root directory */
        MOUNT_FOLLOW_SYMLINKS    = 1 << 11,/* if set, we'll follow symlinks for the mount target */
} MountSettingsMask;

typedef enum CustomMountType {
        CUSTOM_MOUNT_BIND,
        CUSTOM_MOUNT_TMPFS,
        CUSTOM_MOUNT_OVERLAY,
        CUSTOM_MOUNT_INACCESSIBLE,
        CUSTOM_MOUNT_ARBITRARY,
        _CUSTOM_MOUNT_TYPE_MAX,
        _CUSTOM_MOUNT_TYPE_INVALID = -EINVAL,
} CustomMountType;

typedef struct CustomMount {
        CustomMountType type;
        bool read_only;
        char *source; /* for overlayfs this is the upper directory */
        char *destination;
        char *options;
        char *work_dir;
        char **lower;
        char *rm_rf_tmpdir;
        char *type_argument; /* only for CUSTOM_MOUNT_ARBITRARY */
        bool graceful;
        bool in_userns;
} CustomMount;

CustomMount* custom_mount_add(CustomMount **l, size_t *n, CustomMountType t);
void custom_mount_free_all(CustomMount *l, size_t n);
int custom_mount_prepare_all(const char *dest, CustomMount *l, size_t n);

int bind_mount_parse(CustomMount **l, size_t *n, const char *s, bool read_only);
int tmpfs_mount_parse(CustomMount **l, size_t *n, const char *s);
int overlay_mount_parse(CustomMount **l, size_t *n, const char *s, bool read_only);
int inaccessible_mount_parse(CustomMount **l, size_t *n, const char *s);

int mount_all(const char *dest, MountSettingsMask mount_settings, uid_t uid_shift, const char *selinux_apifs_context);
int mount_sysfs(const char *dest, MountSettingsMask mount_settings);

int mount_custom(const char *dest, CustomMount *mounts, size_t n, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context, MountSettingsMask mount_settings);
bool has_custom_root_mount(const CustomMount *mounts, size_t n);

int setup_volatile_mode(const char *directory, VolatileMode mode, uid_t uid_shift, const char *selinux_apifs_context);

int pivot_root_parse(char **pivot_root_new, char **pivot_root_old, const char *s);
int setup_pivot_root(const char *directory, const char *pivot_root_new, const char *pivot_root_old);

int tmpfs_patch_options(const char *options,uid_t uid_shift, const char *selinux_apifs_context, char **ret);
