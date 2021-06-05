/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "networkd-link.h"

extern const sd_bus_vtable dhcp_server_vtable[];

void dhcp_server_callback(sd_dhcp_server *server, uint64_t event, void *data);
