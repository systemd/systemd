/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "hash-funcs.h"
#include "iovec-util.h"
#include "macro-fundamental.h"
#include "set.h"

typedef struct DNSServer DNSServer;
typedef struct SearchDomain SearchDomain;
typedef struct DNSConfiguration DNSConfiguration;

struct DNSServer {
        struct iovec addr;
        int family;
        uint16_t port;
        int ifindex;
        char *server_name;
        bool accessible;
};

DNSServer* dns_server_free(DNSServer *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSServer*, dns_server_free);

struct SearchDomain {
        char *name;
        bool route_only;
        int ifindex;
};

SearchDomain* search_domain_free(SearchDomain *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(SearchDomain*, search_domain_free);

struct DNSConfiguration {
        char *ifname;
        int ifindex;
        bool default_route;
        DNSServer *current_dns_server;
        Set *dns_servers;
        Set *search_domains;
};

DNSConfiguration* dns_configuration_free(DNSConfiguration *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSConfiguration*, dns_configuration_free);

int dns_configuration_from_json(sd_json_variant *variant, DNSConfiguration **ret);
bool dns_is_accessible(DNSConfiguration *c);
bool dns_configuration_contains_search_domain(DNSConfiguration *c, const char *domain);

extern const struct hash_ops dns_configuration_hash_ops;
