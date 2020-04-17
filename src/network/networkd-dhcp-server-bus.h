/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "networkd-link.h"

extern const sd_dhcp_server_cb dhcp_server_cb;

extern const sd_bus_vtable dhcp_server_vtable[];
