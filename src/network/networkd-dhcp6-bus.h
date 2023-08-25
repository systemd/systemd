/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-client.h"

#include "dhcp6-protocol.h"
#include "networkd-link-bus.h"

extern const BusObjectImplementation dhcp6_client_object;

void dhcp6_client_callback_bus(sd_dhcp6_client *client, int event, void *userdata);
const char* dhcp6_client_state_to_string(DHCP6State s) _const_;
