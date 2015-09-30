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

typedef struct Device Device;

typedef enum DeviceFound {
        DEVICE_NOT_FOUND = 0,
        DEVICE_FOUND_UDEV = 1,
        DEVICE_FOUND_MOUNT = 2,
        DEVICE_FOUND_SWAP = 4,
} DeviceFound;

struct Device {
        Unit meta;

        char *sysfs;
        DeviceFound found;

        /* In order to be able to distinguish dependencies on
        different device nodes we might end up creating multiple
        devices for the same sysfs path. We chain them up here. */
        LIST_FIELDS(struct Device, same_sysfs);

        DeviceState state, deserialized_state;
};

extern const UnitVTable device_vtable;

int device_found_node(Manager *m, const char *node, bool add, DeviceFound found, bool now);
