/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

extern const BusObjectImplementation dhcp_client_object;

int dhcp_client_callback_bus(sd_dhcp_client *client, int event, void *userdata);
