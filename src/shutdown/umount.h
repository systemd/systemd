/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2010 ProFUSION embedded systems
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
