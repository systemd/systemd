/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdint.h>
#include <linux/if_packet.h>

#include "socket-util.h"

#include "sd-dhcp-client.h"
#include "dhcp-protocol.h"

int dhcp_network_bind_raw_socket(int index, union sockaddr_union *link, uint32_t xid);
int dhcp_network_bind_udp_socket(be32_t address, uint16_t port);
int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len);
int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port,
                                 const void *packet, size_t len);

int dhcp_option_append(DHCPMessage *message, size_t size, size_t *offset, uint8_t overload,
                       uint8_t code, size_t optlen, const void *optval);

typedef int (*dhcp_option_cb_t)(uint8_t code, uint8_t len,
                                const uint8_t *option, void *user_data);

int dhcp_option_parse(DHCPMessage *message, size_t len,
                      dhcp_option_cb_t cb, void *user_data);

int dhcp_message_init(DHCPMessage *message, uint8_t op, uint32_t xid, uint8_t type,
                      size_t optlen, size_t *optoffset);

uint16_t dhcp_packet_checksum(uint8_t *buf, size_t len);

void dhcp_packet_append_ip_headers(DHCPPacket *packet, be32_t source_addr,
                                   uint16_t source, be32_t destination_addr,
                                   uint16_t destination, uint16_t len);

int dhcp_packet_verify_headers(DHCPPacket *packet, size_t len, bool checksum);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_client*, sd_dhcp_client_unref);
#define _cleanup_dhcp_client_unref_ _cleanup_(sd_dhcp_client_unrefp)

/* If we are invoking callbacks of a dhcp-client, ensure unreffing the
 * client from the callback doesn't destroy the object we are working
 * on */
#define DHCP_CLIENT_DONT_DESTROY(client) \
        _cleanup_dhcp_client_unref_ _unused_ sd_dhcp_client *_dont_destroy_##client = sd_dhcp_client_ref(client)

#define log_dhcp_client(client, fmt, ...) log_meta(LOG_DEBUG, __FILE__, __LINE__, __func__, "DHCP CLIENT (0x%x): " fmt, client->xid, ##__VA_ARGS__)
