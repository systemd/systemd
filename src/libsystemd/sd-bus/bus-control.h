/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int bus_add_match_internal(sd_bus *bus, const char *match, uint64_t timeout_usec, uint64_t *ret_counter);
int bus_add_match_internal_async(sd_bus *bus, sd_bus_slot **ret, const char *match, sd_bus_message_handler_t callback, void *userdata, uint64_t timeout_usec);

int bus_remove_match_internal(sd_bus *bus, const char *match);
