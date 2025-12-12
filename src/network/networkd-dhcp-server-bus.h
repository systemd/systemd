/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

extern const BusObjectImplementation dhcp_server_object;

void dhcp_server_callback(sd_dhcp_server *server, uint64_t event, void *data);
