/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-protocol.h"

int dhcp_client_send_raw(
                sd_dhcp_client *client,
                bool expect_reply,
                DHCPPacket *packet,
                size_t optoffset);

int dhcp_client_send_udp(
                sd_dhcp_client *client,
                bool expect_reply,
                DHCPPacket *packet,
                size_t optoffset);
