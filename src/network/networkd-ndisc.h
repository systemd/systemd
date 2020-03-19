/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "time-util.h"

typedef struct IPv6Token IPv6Token;

typedef enum IPv6TokenAddressGeneration {
        IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        IPV6_TOKEN_ADDRESS_GENERATION_STATIC,
        IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE,
        _IPV6_TOKEN_ADDRESS_GENERATION_MAX,
        _IPV6_TOKEN_ADDRESS_GENERATION_INVALID = -1,
} IPv6TokenAddressGeneration;

typedef struct NDiscRDNSS {
        usec_t valid_until;
        struct in6_addr address;
} NDiscRDNSS;

typedef struct NDiscDNSSL {
        usec_t valid_until;
        /* The domain name follows immediately. */
} NDiscDNSSL;

struct IPv6Token {
        IPv6TokenAddressGeneration address_generation_type;

        uint8_t dad_counter;
        struct in6_addr prefix;
};

int ipv6token_new(IPv6Token **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(IPv6Token *, freep);

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

int ndisc_configure(Link *link);
void ndisc_vacuum(Link *link);
void ndisc_flush(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ndisc_black_listed_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_address_generation_type);
