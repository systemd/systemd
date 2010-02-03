/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomounthfoo
#define foomounthfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct Mount Mount;

#include "unit.h"

typedef enum MountState {
        MOUNT_DEAD,
        MOUNT_MOUNTING,
        MOUNT_MOUNTED,
        MOUNT_UNMOUNTING,
        MOUNT_MAINTAINANCE,
        _MOUNT_STATE_MAX
} MountState;

struct Mount {
        Meta meta;

        MountState state;

        char *what, *where;

        bool from_etc_fstab:1;
        bool from_proc_self_mountinfo:1;

        /* Used while looking for mount points that vanished or got
         * added from/to /proc/self/mountinfo */
        bool still_exists:1;
        bool just_created:1;
};

extern const UnitVTable mount_vtable;

void mount_fd_event(Manager *m, int events);

#endif
