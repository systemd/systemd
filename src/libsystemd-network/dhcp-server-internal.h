/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#pragma once

#include "sd-event.h"
#include "sd-dhcp-server.h"

#include "hashmap.h"
#include "refcnt.h"
#include "util.h"
#include "log.h"

#include "dhcp-internal.h"

typedef struct DHCPClientId {
        size_t length;
        uint8_t *data;
} DHCPClientId;

typedef struct DHCPLease {
        DHCPClientId client_id;

        be32_t address;
        be32_t gateway;
        uint8_t chaddr[16];
        usec_t expiration;
} DHCPLease;

struct sd_dhcp_server {
        RefCount n_ref;

        sd_event *event;
        int event_priority;
        sd_event_source *receive_message;
        int fd;
        int fd_raw;

        int index;
        be32_t address;
        be32_t netmask;
        be32_t pool_start;
        size_t pool_size;
        size_t next_offer;

        Hashmap *leases_by_client_id;
        DHCPLease **bound_leases;
};

typedef struct DHCPRequest {
        /* received message */
        DHCPMessage *message;

        /* options */
        DHCPClientId client_id;
        size_t max_optlen;
        be32_t server_id;
        be32_t requested_ip;
        int lifetime;
} DHCPRequest;

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_server*, sd_dhcp_server_unref);
#define _cleanup_dhcp_server_unref_ _cleanup_(sd_dhcp_server_unrefp)

#define log_dhcp_server(client, fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "DHCP SERVER: " fmt, ##__VA_ARGS__)

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message,
                               size_t length);
int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset);

unsigned long client_id_hash_func(const void *p, const uint8_t hash_key[HASH_KEY_SIZE]);
int client_id_compare_func(const void *_a, const void *_b);
