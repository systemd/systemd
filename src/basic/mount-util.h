#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <fcntl.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "missing.h"

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

union file_handle_union {
        struct file_handle handle;
        char padding[sizeof(struct file_handle) + MAX_HANDLE_SZ];
};

const char* mode_to_inaccessible_node(mode_t mode);

#define FILE_HANDLE_INIT { .handle.handle_bytes = MAX_HANDLE_SZ }

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
