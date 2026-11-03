/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dhcp-forward.h"

bool dhcp_server_want_ipv6_only_preferred(sd_dhcp_server *server, DHCPRequest *req);

int dhcp_server_send_reply(
                sd_dhcp_server *server,
                DHCPRequest *req,
                uint8_t type);
