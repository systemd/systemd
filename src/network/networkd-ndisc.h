/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "dns-resolver-internal.h"
#include "time-util.h"

typedef struct Address Address;
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
        struct in6_addr router;
        /* This is an absolute point in time, and NOT a timespan/duration.
         * Must be specified with CLOCK_BOOTTIME. */
        usec_t lifetime_usec;
        struct in6_addr address;
} NDiscRDNSS;

typedef struct NDiscDNSSL {
        struct in6_addr router;
        /* This is an absolute point in time, and NOT a timespan/duration.
         * Must be specified with CLOCK_BOOTTIME. */
        usec_t lifetime_usec;
        /* The domain name follows immediately. */
} NDiscDNSSL;

typedef struct NDiscCaptivePortal {
        struct in6_addr router;
        /* This is an absolute point in time, and NOT a timespan/duration.
         * Must be specified with CLOCK_BOOTTIME. */
        usec_t lifetime_usec;
        char *captive_portal;
} NDiscCaptivePortal;

typedef struct NDiscPREF64 {
        struct in6_addr router;
        /* This is an absolute point in time, and NOT a timespan/duration.
         * Must be specified with CLOCK_BOOTTIME. */
        usec_t lifetime_usec;
        uint8_t prefix_len;
        struct in6_addr prefix;
} NDiscPREF64;

typedef struct NDiscDNR {
        struct in6_addr router;
        usec_t lifetime_usec;
        sd_dns_resolver resolver;
} NDiscDNR;

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

bool link_ndisc_enabled(Link *link);

void network_adjust_ndisc(Network *network);

int ndisc_start(Link *link);
int ndisc_stop(Link *link);
void ndisc_flush(Link *link);

int link_request_ndisc(Link *link);
int link_drop_ndisc_config(Link *link, Network *network);
int ndisc_reconfigure_address(Address *address, Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ndisc_start_dhcp6_client);
