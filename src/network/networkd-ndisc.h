/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-route.h"
#include "time-util.h"

typedef struct IPv6Token IPv6Token;

typedef enum IPv6TokenAddressGeneration {
        IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        IPV6_TOKEN_ADDRESS_GENERATION_STATIC,
        IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE,
        _IPV6_TOKEN_ADDRESS_GENERATION_MAX,
        _IPV6_TOKEN_ADDRESS_GENERATION_INVALID = -EINVAL,
} IPv6TokenAddressGeneration;

typedef enum IPv6AcceptRAStartDHCP6Client {
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO,
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS,
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES,
        _IPV6_ACCEPT_RA_START_DHCP6_CLIENT_MAX,
        _IPV6_ACCEPT_RA_START_DHCP6_CLIENT_INVALID = -EINVAL,
} IPv6AcceptRAStartDHCP6Client;

typedef struct NDiscAddress {
        /* Used when GC'ing old DNS servers when configuration changes. */
        bool marked;
        struct in6_addr router;
        Address *address;
} NDiscAddress;

typedef struct NDiscRoute {
        /* Used when GC'ing old DNS servers when configuration changes. */
        bool marked;
        struct in6_addr router;
        Route *route;
} NDiscRoute;

typedef struct NDiscRDNSS {
        /* Used when GC'ing old DNS servers when configuration changes. */
        bool marked;
        struct in6_addr router;
        usec_t valid_until;
        struct in6_addr address;
} NDiscRDNSS;

typedef struct NDiscDNSSL {
        /* Used when GC'ing old domains when configuration changes. */
        bool marked;
        struct in6_addr router;
        usec_t valid_until;
        /* The domain name follows immediately. */
} NDiscDNSSL;

struct IPv6Token {
        IPv6TokenAddressGeneration address_generation_type;

        uint8_t dad_counter;
        struct in6_addr prefix;
};

int ipv6token_new(IPv6Token **ret);

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

bool link_ipv6_accept_ra_enabled(Link *link);

void network_adjust_ipv6_accept_ra(Network *network);

int ndisc_configure(Link *link);
void ndisc_vacuum(Link *link);
void ndisc_flush(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ndisc_address_filter);
CONFIG_PARSER_PROTOTYPE(config_parse_address_generation_type);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_accept_ra_start_dhcp6_client);

const char* ipv6_accept_ra_start_dhcp6_client_to_string(IPv6AcceptRAStartDHCP6Client i) _const_;
IPv6AcceptRAStartDHCP6Client ipv6_accept_ra_start_dhcp6_client_from_string(const char *s) _pure_;
