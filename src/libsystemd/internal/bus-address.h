/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

char* bus_address_escape(const char *v);
int bus_set_address_system(sd_bus *bus);
int bus_set_address_user(sd_bus *bus);
int bus_set_address_system_remote(sd_bus *b, const char *host);
int bus_set_address_machine(sd_bus *b, bool user, const char *machine);
