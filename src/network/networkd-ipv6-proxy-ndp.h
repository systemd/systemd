/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "list.h"
#include "macro.h"

typedef struct Network Network;
typedef struct IPv6ProxyNDPAddress IPv6ProxyNDPAddress;
typedef struct Link Link;

struct IPv6ProxyNDPAddress {
        Network *network;
        struct in6_addr in_addr;

        LIST_FIELDS(IPv6ProxyNDPAddress, ipv6_proxy_ndp_addresses);
};

void ipv6_proxy_ndp_address_free(IPv6ProxyNDPAddress *ipv6_proxy_ndp_address);
int ipv6_proxy_ndp_address_configure(Link *link, IPv6ProxyNDPAddress *ipv6_proxy_ndp_address);
int ipv6_proxy_ndp_addresses_configure(Link *link);

DEFINE_TRIVIAL_CLEANUP_FUNC(IPv6ProxyNDPAddress*, ipv6_proxy_ndp_address_free);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_proxy_ndp_address);
