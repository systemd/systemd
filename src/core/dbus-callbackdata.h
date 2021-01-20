/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "selinux-core-access.h"

typedef struct MacUnitCallbackUserdata {
        Manager *manager;
        sd_bus_message *message;
        sd_bus_error *error;
        const char *func;

        mac_selinux_unit_permission selinux_permission;
} MacUnitCallbackUserdata;
