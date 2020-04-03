/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2012 Dan Walsh
***/

#include "sd-bus.h"

#include "bus-util.h"
#include "manager.h"

int mac_selinux_generic_access_check(sd_bus_message *message, const char *path, const char *permission, sd_bus_error *error);

#define mac_selinux_access_check(message, permission, error) \
        mac_selinux_generic_access_check((message), NULL, (permission), (error))

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        mac_selinux_generic_access_check((message), unit_label_path(unit), (permission), (error))
