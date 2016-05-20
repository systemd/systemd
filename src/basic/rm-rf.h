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

#include <sys/stat.h>

typedef enum RemoveFlags {
        REMOVE_ONLY_DIRECTORIES = 1,
        REMOVE_ROOT = 2,
        REMOVE_PHYSICAL = 4, /* if not set, only removes files on tmpfs, never physical file systems */
        REMOVE_SUBVOLUME = 8,
} RemoveFlags;

int rm_rf_children(int fd, RemoveFlags flags, struct stat *root_dev);
int rm_rf(const char *path, RemoveFlags flags);

/* Useful for usage with _cleanup_(), destroys a directory and frees the pointer */
static inline void rm_rf_physical_and_free(char *p) {
        if (!p)
                return;
        (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rm_rf_physical_and_free);
