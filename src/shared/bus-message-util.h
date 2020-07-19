/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "in-addr-util.h"

int bus_message_read_family(sd_bus_message *message, sd_bus_error *error, int *ret);
int bus_message_read_in_addr_auto(sd_bus_message *message, sd_bus_error *error, int *ret_family, union in_addr_union *ret_addr);
