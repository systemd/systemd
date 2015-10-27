/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <sys/stat.h>
#include <sys/types.h>

#include "missing.h"

int fd_is_mount_point(int fd, const char *filename, int flags);
int path_is_mount_point(const char *path, int flags);

int repeat_unmount(const char *path, int flags);

int umount_recursive(const char *target, int flags);
int bind_remount_recursive(const char *prefix, bool ro);

int mount_move_root(const char *path);

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, endmntent);
#define _cleanup_endmntent_ _cleanup_(endmntentp)

bool fstype_is_network(const char *fstype);

union file_handle_union {
        struct file_handle handle;
        char padding[sizeof(struct file_handle) + MAX_HANDLE_SZ];
};

#define FILE_HANDLE_INIT { .handle.handle_bytes = MAX_HANDLE_SZ }
