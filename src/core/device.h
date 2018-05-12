/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

typedef struct Device Device;

typedef enum DeviceFound {
        DEVICE_NOT_FOUND     = 0,
        DEVICE_FOUND_UDEV    = 1 << 1,
        DEVICE_FOUND_UDEV_DB = 1 << 2,
        DEVICE_FOUND_MOUNT   = 1 << 3,
        DEVICE_FOUND_SWAP    = 1 << 4,
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

        bool bind_mounts;
};

extern const UnitVTable device_vtable;

int device_found_node(Manager *m, const char *node, bool add, DeviceFound found, bool now);
bool device_shall_be_bound_by(Unit *device, Unit *u);
