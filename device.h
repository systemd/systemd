/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foodevicehfoo
#define foodevicehfoo

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

typedef struct Device Device;

#include "unit.h"

/* We simply watch devices, we cannot plug/unplug them. That
 * simplifies the state engine greatly */
typedef enum DeviceState {
        DEVICE_DEAD,
        DEVICE_AVAILABLE,
        _DEVICE_STATE_MAX
} DeviceState;

struct Device {
        Meta meta;

        DeviceState state;

        /* A single device can be created by multiple sysfs objects */
        char *sysfs;
};

extern const UnitVTable device_vtable;

void device_fd_event(Manager *m, int events);

#endif
