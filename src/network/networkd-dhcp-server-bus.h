/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-dhcp-server.h"

#include "bus-object.h"

extern const BusObjectImplementation dhcp_server_object;

void dhcp_server_callback(sd_dhcp_server *server, uint64_t event, void *data);
