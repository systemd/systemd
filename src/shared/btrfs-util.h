/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdbool.h>
#include <sys/types.h>

int btrfs_is_snapshot(int fd);

int btrfs_subvol_make(const char *path);
int btrfs_subvol_remove(const char *path);
int btrfs_subvol_snapshot(const char *old_path, const char *new_path, bool read_only, bool fallback_copy);
int btrfs_subvol_read_only(const char *path, bool b);
int btrfs_subvol_is_read_only_fd(int fd);

int btrfs_reflink(int infd, int outfd);

int btrfs_get_block_device(const char *path, dev_t *dev);
