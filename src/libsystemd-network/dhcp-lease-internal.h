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

struct sd_dhcp_lease {
        unsigned n_ref;

        sd_dhcp_message *message;

        /* each 0 if unset */
        usec_t t1;
        usec_t t2;
        usec_t lifetime;
        triple_timestamp timestamp;
        usec_t ipv6_only_preferred_usec;

        /* each 0 if unset */
        be32_t address;
        be32_t server_address;
        be32_t subnet_mask;
        be32_t broadcast;

        struct in_addr *router;
        size_t router_size;

        DHCPServerData servers[_SD_DHCP_LEASE_SERVER_TYPE_MAX];

        sd_dns_resolver *dnr;
        size_t n_dnr;

        struct sd_dhcp_route *static_routes;
        size_t n_static_routes;
        struct sd_dhcp_route *classless_routes;
        size_t n_classless_routes;

        uint16_t mtu; /* 0 if unset */

        char *domainname;
        char **search_domains;
        char *hostname;
        char *captive_portal;

        char *timezone;

        uint8_t sixrd_ipv4masklen;
        uint8_t sixrd_prefixlen;
        struct in6_addr sixrd_prefix;
        struct in_addr *sixrd_br_addresses;
        size_t sixrd_n_br_addresses;
};

int dhcp_lease_new(sd_dhcp_lease **ret);

void dhcp_lease_set_timestamp(sd_dhcp_lease *lease, const triple_timestamp *timestamp);

int dhcp_client_parse_message(sd_dhcp_client *client, const struct iovec *iov, sd_dhcp_lease **ret);
