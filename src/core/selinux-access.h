/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "bus-util.h"
#include "manager.h"

int mac_selinux_generic_access_check(sd_bus_message *message, const char *path, const char *permission, sd_bus_error *error);

#if HAVE_SELINUX

#define mac_selinux_access_check(message, permission, error) \
        mac_selinux_generic_access_check((message), NULL, (permission), (error))

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        mac_selinux_generic_access_check((message), unit_label_path(unit), (permission), (error))

#else

#define mac_selinux_access_check(message, permission, error) 0
#define mac_selinux_unit_access_check(unit, message, permission, error) 0

#endif
