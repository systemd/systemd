/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-server-request.h"

int server_send_offer_or_ack(
                sd_dhcp_server *server,
                DHCPRequest *req,
                be32_t address,
                uint8_t type);

int server_send_nak_or_ignore(sd_dhcp_server *server, bool init_reboot, DHCPRequest *req);
