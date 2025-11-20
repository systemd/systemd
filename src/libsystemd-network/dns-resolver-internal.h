/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dns-resolver.h"

#include "sd-forward.h"
#include "socket-netlink.h"

/* Represents a "designated resolver" */
/* typedef struct sd_dns_resolver sd_dns_resolver; */
typedef struct sd_dns_resolver {
        uint16_t priority;
        char *auth_name;
        int family;
        union in_addr_union *addrs;
        size_t n_addrs;
        sd_dns_alpn_flags transports;
        uint16_t port;
        char *dohpath;
} sd_dns_resolver;

void siphash24_compress_resolver(const sd_dns_resolver *res, struct siphash *state);

int dns_resolver_transports_to_strv(sd_dns_alpn_flags transports, char ***ret);

int dns_resolvers_to_dot_addrs(const sd_dns_resolver *resolvers, size_t n_resolvers,
                struct in_addr_full ***ret_addrs, size_t *ret_n_addrs);

int dns_resolver_prio_compare(const sd_dns_resolver *a, const sd_dns_resolver *b);

int dnr_parse_svc_params(const uint8_t *option, size_t len, sd_dns_resolver *resolver);

int dns_resolvers_to_dot_strv(const sd_dns_resolver *resolvers, size_t n_resolvers, char ***ret_names);

void sd_dns_resolver_done(sd_dns_resolver *res);

void dns_resolver_done_many(sd_dns_resolver *resolvers, size_t n);
