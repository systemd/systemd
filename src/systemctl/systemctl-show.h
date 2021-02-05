/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

int get_unit_dbus_path_by_pid(sd_bus *bus, uint32_t pid, char **unit);
int show(int argc, char *argv[], void *userdata);
