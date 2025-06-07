/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "logind-forward.h"
#include "time-util.h"

typedef struct Device {
        Manager *manager;

        char *sysfs;
        Seat *seat;
        bool master;

        dual_timestamp timestamp;

        LIST_FIELDS(Device, devices);
        LIST_HEAD(SessionDevice, session_devices);
} Device;

Device* device_new(Manager *m, const char *sysfs, bool master);
void device_free(Device *d);
void device_attach(Device *d, Seat *s);
