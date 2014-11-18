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

#include "refcnt.h"
#include "util.h"

#include "dhcp-protocol.h"

#include "sd-dhcp-client.h"

struct sd_dhcp_route {
        struct in_addr dst_addr;
        struct in_addr gw_addr;
        unsigned char dst_prefixlen;
};

struct sd_dhcp_lease {
        RefCount n_ref;

        int32_t time_offset;
        uint32_t t1;
        uint32_t t2;
        uint32_t lifetime;
        uint32_t mtu_aging_timeout;
        be32_t address;
        be32_t server_address;
        be32_t subnet_mask;
        be32_t router;
        be32_t next_server;
        be32_t broadcast;
        struct in_addr *dns;
        size_t dns_size;
        struct in_addr *ntp;
        size_t ntp_size;
        struct in_addr *policy_filter;
        size_t policy_filter_size;
        struct sd_dhcp_route *static_route;
        size_t static_route_size;
        size_t static_route_allocated;
        uint16_t boot_file_size;
        uint16_t mdr;
        uint16_t mtu;
        uint8_t ttl;
        bool ip_forward;
        bool ip_forward_non_local;
        char *domainname;
        char *hostname;
        char *root_path;
        uint8_t *client_id;
        size_t client_id_len;
};

int dhcp_lease_new(sd_dhcp_lease **ret);
int dhcp_lease_parse_options(uint8_t code, uint8_t len, const uint8_t *option,
                              void *user_data);

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease);

int dhcp_lease_set_client_id(sd_dhcp_lease *lease, const uint8_t *client_id,
                             size_t client_id_len);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_lease*, sd_dhcp_lease_unref);
#define _cleanup_dhcp_lease_unref_ _cleanup_(sd_dhcp_lease_unrefp)
