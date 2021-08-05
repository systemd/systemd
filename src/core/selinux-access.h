/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "manager.h"

/* forward declaration */
typedef struct MacUnitCallbackUserdata MacUnitCallbackUserdata;

int _mac_selinux_generic_access_check(sd_bus_message *message,
                                      const char *path,
                                      const char *permission,
                                      sd_bus_error *error,
                                      const char *func);

#define mac_selinux_access_check(message, permission, error) \
        _mac_selinux_generic_access_check((message), NULL, (permission), (error), __func__)

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        _mac_selinux_generic_access_check((message), unit_label_path(unit), (permission), (error), __func__)

int mac_selinux_unit_callback_check(
                const char *unit_name,
                const MacUnitCallbackUserdata *userdata);
