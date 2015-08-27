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

#include "util.h"
#include "list.h"

#include "dhcp-protocol.h"

#include "sd-dhcp-client.h"

struct sd_dhcp_route {
        struct in_addr dst_addr;
        struct in_addr gw_addr;
        unsigned char dst_prefixlen;
};

struct sd_dhcp_raw_option {
        LIST_FIELDS(struct sd_dhcp_raw_option, options);

        uint8_t tag;
        uint8_t length;
        void *data;
};

struct sd_dhcp_lease {
        unsigned n_ref;

        /* each 0 if unset */
        uint32_t t1;
        uint32_t t2;
        uint32_t lifetime;

        /* each 0 if unset */
        be32_t address;
        be32_t server_address;
        be32_t router;
        be32_t next_server;

        bool have_subnet_mask;
        be32_t subnet_mask;

        bool have_broadcast;
        be32_t broadcast;

        struct in_addr *dns;
        size_t dns_size;

        struct in_addr *ntp;
        size_t ntp_size;

        struct sd_dhcp_route *static_route;
        size_t static_route_size, static_route_allocated;

        uint16_t mtu; /* 0 if unset */

        char *domainname;
        char *hostname;
        char *root_path;

        void *client_id;
        size_t client_id_len;

        void *vendor_specific;
        size_t vendor_specific_len;

        char *timezone;

        LIST_HEAD(struct sd_dhcp_raw_option, private_options);
};

int dhcp_lease_new(sd_dhcp_lease **ret);

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const void *option, void *userdata);
int dhcp_lease_insert_private_option(sd_dhcp_lease *lease, uint8_t tag, const void *data, uint8_t len);

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease);

int dhcp_lease_set_client_id(sd_dhcp_lease *lease, const void *client_id, size_t client_id_len);

int dhcp_lease_save(sd_dhcp_lease *lease, const char *lease_file);
int dhcp_lease_load(sd_dhcp_lease **ret, const char *lease_file);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_lease*, sd_dhcp_lease_unref);
#define _cleanup_dhcp_lease_unref_ _cleanup_(sd_dhcp_lease_unrefp)
