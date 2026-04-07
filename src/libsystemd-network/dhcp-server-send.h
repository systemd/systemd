/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-message.h"
#include "dhcp-server-request.h"

int dhcp_server_send_udp(
                sd_dhcp_server *server,
                be32_t destination,
                uint16_t destination_port,
                sd_dhcp_message *message);

int dhcp_server_send_message(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
                uint8_t type,
                sd_dhcp_message *message);

int dhcp_server_send_reply(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
                uint8_t type);
