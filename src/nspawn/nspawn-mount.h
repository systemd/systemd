/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <stdbool.h>

typedef enum VolatileMode {
        VOLATILE_NO,
        VOLATILE_YES,
        VOLATILE_STATE,
        _VOLATILE_MODE_MAX,
        _VOLATILE_MODE_INVALID = -1
} VolatileMode;

typedef enum CustomMountType {
        CUSTOM_MOUNT_BIND,
        CUSTOM_MOUNT_TMPFS,
        CUSTOM_MOUNT_OVERLAY,
        _CUSTOM_MOUNT_TYPE_MAX,
        _CUSTOM_MOUNT_TYPE_INVALID = -1
} CustomMountType;

typedef struct CustomMount {
        CustomMountType type;
        bool read_only;
        char *source; /* for overlayfs this is the upper directory */
        char *destination;
        char *options;
        char *work_dir;
        char **lower;
} CustomMount;

CustomMount* custom_mount_add(CustomMount **l, unsigned *n, CustomMountType t);

void custom_mount_free_all(CustomMount *l, unsigned n);
int bind_mount_parse(CustomMount **l, unsigned *n, const char *s, bool read_only);
int tmpfs_mount_parse(CustomMount **l, unsigned *n, const char *s);

int custom_mount_compare(const void *a, const void *b);

int mount_all(const char *dest, bool use_userns, bool in_userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context);
int mount_sysfs(const char *dest);

int mount_cgroups(const char *dest, bool unified_requested, bool userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context);
int mount_systemd_cgroup_writable(const char *dest, bool unified_requested);

int mount_custom(const char *dest, CustomMount *mounts, unsigned n, bool userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context);

int setup_volatile(const char *directory, VolatileMode mode, bool userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context);
int setup_volatile_state(const char *directory, VolatileMode mode, bool userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context);

VolatileMode volatile_mode_from_string(const char *s);
