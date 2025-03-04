/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <stdbool.h>
#include <stdio.h>

#include "list.h"

int umount_all(bool *changed, bool last_try);

/* This is exported just for testing */
typedef struct MountPoint {
        char *path;
        char *remount_options;
        unsigned long remount_flags;
        bool try_remount_ro;
        bool umount_lazily;
        bool leaf;
        LIST_FIELDS(struct MountPoint, mount_point);
} MountPoint;

int mount_points_list_get(FILE *f, MountPoint **head);
void mount_points_list_free(MountPoint **head);
