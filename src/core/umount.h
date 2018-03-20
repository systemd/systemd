/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

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

#include "list.h"

int umount_all(bool *changed, int umount_log_level);

int swapoff_all(bool *changed);

int loopback_detach_all(bool *changed, int umount_log_level);

int dm_detach_all(bool *changed, int umount_log_level);

/* This is exported just for testing */
typedef struct MountPoint {
        char *path;
        char *remount_options;
        unsigned long remount_flags;
        bool try_remount_ro;
        dev_t devnum;
        LIST_FIELDS(struct MountPoint, mount_point);
} MountPoint;

int mount_points_list_get(const char *mountinfo, MountPoint **head);
void mount_points_list_free(MountPoint **head);
int swap_list_get(const char *swaps, MountPoint **head);
