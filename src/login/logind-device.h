/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include "list.h"
#include "logind-seat.h"
#include "logind-session-device.h"

struct Device {
        Manager *manager;

        char *sysfs;
        Seat *seat;
        bool master;

        dual_timestamp timestamp;

        LIST_FIELDS(struct Device, devices);
        LIST_HEAD(SessionDevice, session_devices);
};

Device* device_new(Manager *m, const char *sysfs, bool master);
void device_free(Device *d);
void device_attach(Device *d, Seat *s);
