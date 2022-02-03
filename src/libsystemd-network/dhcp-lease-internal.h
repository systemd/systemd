/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-client.h"

#include "dhcp-internal.h"
#include "dhcp-protocol.h"
#include "list.h"
#include "util.h"

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
        be32_t next_server;

        bool have_subnet_mask;
        be32_t subnet_mask;

        bool have_broadcast;
        be32_t broadcast;

        struct in_addr *router;
        size_t router_size;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];

        struct sd_dhcp_route *static_routes;
        size_t n_static_routes;
        struct sd_dhcp_route *classless_routes;
        size_t n_classless_routes;

        uint16_t mtu; /* 0 if unset */

        char *domainname;
        char **search_domains;
        char *hostname;
        char *root_path;

        void *client_id;
        size_t client_id_len;

        void *vendor_specific;
        size_t vendor_specific_len;

        char *timezone;

        uint8_t sixrd_ipv4masklen;
        uint8_t sixrd_prefixlen;
        struct in6_addr sixrd_prefix;
        struct in_addr *sixrd_br_addresses;
        size_t sixrd_n_br_addresses;

        LIST_HEAD(struct sd_dhcp_raw_option, private_options);
};

int dhcp_lease_new(sd_dhcp_lease **ret);

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const void *option, void *userdata);
int dhcp_lease_parse_search_domains(const uint8_t *option, size_t len, char ***domains);
int dhcp_lease_insert_private_option(sd_dhcp_lease *lease, uint8_t tag, const void *data, uint8_t len);

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease);

int dhcp_lease_set_client_id(sd_dhcp_lease *lease, const void *client_id, size_t client_id_len);
