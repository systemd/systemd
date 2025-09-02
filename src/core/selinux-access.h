/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int mac_selinux_access_check_bus_internal(sd_bus_message *message, const Unit *unit, const char *permission, const char *function, sd_bus_error *error);
int mac_selinux_access_check_varlink_internal(sd_varlink *link, const Unit *unit, const char *permission, const char *function);

#define mac_selinux_access_check(message, permission, error) \
        mac_selinux_access_check_bus_internal((message), NULL, (permission), __func__, (error))

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        mac_selinux_access_check_bus_internal((message), (unit), (permission), __func__, (error))

#define mac_selinux_access_check_varlink(link, permission) \
        mac_selinux_access_check_varlink_internal((link), NULL, (permission), __func__)

#define mac_selinux_unit_access_check_varlink(unit, link, permission) \
        mac_selinux_access_check_varlink_internal((link), (unit), (permission), __func__)
