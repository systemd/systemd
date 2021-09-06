/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "time-util.h"

typedef struct Link Link;
typedef struct Network Network;

typedef enum IPv6AcceptRAStartDHCP6Client {
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_NO,
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_ALWAYS,
        IPV6_ACCEPT_RA_START_DHCP6_CLIENT_YES,
        _IPV6_ACCEPT_RA_START_DHCP6_CLIENT_MAX,
        _IPV6_ACCEPT_RA_START_DHCP6_CLIENT_INVALID = -EINVAL,
} IPv6AcceptRAStartDHCP6Client;

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

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

bool link_ipv6_accept_ra_enabled(Link *link);

void network_adjust_ipv6_accept_ra(Network *network);

int ndisc_configure(Link *link);
int ndisc_start(Link *link);
void ndisc_vacuum(Link *link);
void ndisc_flush(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_address_generation_type);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_accept_ra_start_dhcp6_client);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_accept_ra_use_domains);
