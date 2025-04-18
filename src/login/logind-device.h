/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "time-util.h"

typedef struct Device Device;
typedef struct Manager Manager;
typedef struct Seat Seat;
typedef struct SessionDevice SessionDevice;

struct Device {
        Manager *manager;

        char *sysfs;
        Seat *seat;
        bool master;

        dual_timestamp timestamp;

        LIST_FIELDS(Device, devices);
        LIST_HEAD(SessionDevice, session_devices);
};

Device* device_new(Manager *m, const char *sysfs, bool master);
void device_free(Device *d);
void device_attach(Device *d, Seat *s);
