/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-server-request.h"

int dhcp_server_send_reply(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
                uint8_t type);
