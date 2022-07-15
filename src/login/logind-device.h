/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
