/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int mac_selinux_access_check_internal(sd_bus_message *message, const Unit *unit, const char *permission, const char *function, sd_bus_error *error);

#define mac_selinux_access_check(message, permission, error) \
        mac_selinux_access_check_internal((message), NULL, (permission), __func__, (error))

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        mac_selinux_access_check_internal((message), (unit), (permission), __func__, (error))
