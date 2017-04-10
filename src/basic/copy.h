#pragma once

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

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum CopyFlags {
        COPY_REFLINK    = 0x1,      /* try to reflink */
        COPY_MERGE      = 0x2,      /* merge existing trees with our new one to copy */
        COPY_REPLACE    = 0x4,      /* replace an existing file if there's one */
} CopyFlags;

int copy_file_fd(const char *from, int to, CopyFlags copy_flags);
int copy_file(const char *from, const char *to, int open_flags, mode_t mode, unsigned chattr_flags, CopyFlags copy_flags);
int copy_file_atomic(const char *from, const char *to, mode_t mode, unsigned chattr_flags, CopyFlags copy_flags);
int copy_tree(const char *from, const char *to, uid_t override_uid, gid_t override_gid, CopyFlags copy_flags);
int copy_tree_at(int fdf, const char *from, int fdt, const char *to, uid_t override_uid, gid_t override_gid, CopyFlags copy_flags);
int copy_directory_fd(int dirfd, const char *to, CopyFlags copy_flags);
int copy_directory(const char *from, const char *to, CopyFlags copy_flags);
int copy_bytes(int fdf, int fdt, uint64_t max_bytes, CopyFlags copy_flags);
int copy_times(int fdf, int fdt);
int copy_xattr(int fdf, int fdt);
