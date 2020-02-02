/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "selinux-access.h"

struct mac_callback_userdata {
        Manager *manager;
        sd_bus_message *message;
        sd_bus_error *error;
        const char *func;

        enum mac_selinux_unit_permissions selinux_permission;
};
