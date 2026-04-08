/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-lease.h"
#include "sd-forward.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "list.h"

struct sd_dhcp_route {
        struct in_addr dst_addr;
        struct in_addr gw_addr;
        unsigned char dst_prefixlen;
};

struct sd_dhcp_lease {
        unsigned n_ref;

        sd_dhcp_message *message;

        /* each 0 if unset */
        usec_t t1;
        usec_t t2;
        usec_t lifetime;
        triple_timestamp timestamp;

        /* each 0 if unset */
        be32_t address;
        be32_t server_address;
        be32_t subnet_mask;

        struct in_addr *router;
        size_t router_size;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];

        sd_dns_resolver *dnr;
        size_t n_dnr;

        struct sd_dhcp_route *static_routes;
        size_t n_static_routes;
        struct sd_dhcp_route *classless_routes;
        size_t n_classless_routes;

        char *domainname;
        char **search_domains;
        char *hostname;
        char *root_path;
        char *captive_portal;

        char *timezone;

        uint8_t sixrd_ipv4masklen;
        uint8_t sixrd_prefixlen;
        struct in6_addr sixrd_prefix;
        struct in_addr *sixrd_br_addresses;
        size_t sixrd_n_br_addresses;
};

int dhcp_lease_new(sd_dhcp_lease **ret);

int dhcp_lease_parse_search_domains(const uint8_t *option, size_t len, char ***domains);

void dhcp_lease_set_timestamp(sd_dhcp_lease *lease, const triple_timestamp *timestamp);

#define dhcp_lease_unref_and_replace(a, b)                              \
        unref_and_replace_full(a, b, sd_dhcp_lease_ref, sd_dhcp_lease_unref)

int dhcp_lease_new_from_message(sd_dhcp_message *message, sd_dhcp_lease **ret);
int dhcp_client_parse_message(sd_dhcp_client *client, const struct iovec *iov, sd_dhcp_lease **ret);
