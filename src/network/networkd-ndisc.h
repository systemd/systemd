/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "time-util.h"

typedef struct NDiscRDNSS {
        usec_t valid_until;
        struct in6_addr address;
} NDiscRDNSS;

typedef struct NDiscDNSSL {
        usec_t valid_until;
        /* The domain name follows immediately. */
} NDiscDNSSL;

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

int ndisc_configure(Link *link);
void ndisc_vacuum(Link *link);
void ndisc_flush(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ndisc_black_listed_prefix);
