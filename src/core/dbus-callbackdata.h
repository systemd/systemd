/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "manager.h"

typedef struct MacUnitCallbackUserdata {
        Manager *manager;
        sd_bus_message *message;
        sd_bus_error *error;
        const char *function;

        const char *selinux_permission;
} MacUnitCallbackUserdata;
