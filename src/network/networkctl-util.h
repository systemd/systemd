/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-varlink.h"

int varlink_connect_networkd(sd_varlink **ret_varlink);
bool networkd_is_running(void);
int acquire_bus(sd_bus **ret);
int link_get_property(
                sd_bus *bus,
                int ifindex,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *iface,
                const char *propname,
                const char *type);

void operational_state_to_color(const char *name, const char *state, const char **on, const char **off);
void setup_state_to_color(const char *state, const char **on, const char **off);
void online_state_to_color(const char *state, const char **on, const char **off);
