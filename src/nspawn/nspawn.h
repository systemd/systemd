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

#include <inttypes.h>
#include <stdbool.h>

#include "list.h"

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

typedef struct ExposePort {
        int protocol;
        uint16_t host_port;
        uint16_t container_port;
        LIST_FIELDS(struct ExposePort, ports);
} ExposePort;

void custom_mount_free_all(CustomMount *l, unsigned n);
int bind_mount_parse(CustomMount **l, unsigned *n, const char *s, bool read_only);
int tmpfs_mount_parse(CustomMount **l, unsigned *n, const char *s);

void expose_port_free_all(ExposePort *p);
int expose_port_parse(ExposePort **l, const char *s);

VolatileMode volatile_mode_from_string(const char *s);
