/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "in-addr-util.h"
#include "shared-forward.h"

typedef struct DNSServer {
        struct iovec addr;
        int family;
        uint16_t port;
        int ifindex;
        char *server_name;
        bool accessible;
        union in_addr_union in_addr;
} DNSServer;

DNSServer* dns_server_free(DNSServer *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSServer*, dns_server_free);

typedef struct SearchDomain {
        char *name;
        bool route_only;
        int ifindex;
} SearchDomain;

typedef struct DNSScope {
        char *ifname;
        int ifindex;
        char *protocol;
        int family;
        char *dnssec_mode_str;
        char *dns_over_tls_mode_str;
} DNSScope;

DNSScope* dns_scope_free(DNSScope *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSScope*, dns_scope_free);

SearchDomain* search_domain_free(SearchDomain *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(SearchDomain*, search_domain_free);

typedef struct DNSConfiguration {
        char *ifname;
        int ifindex;
        bool default_route;
        DNSServer *current_dns_server;
        OrderedSet *dns_servers;
        OrderedSet *search_domains;
        OrderedSet *fallback_dns_servers;
        Set *dns_scopes;
        char *dnssec_mode_str;
        char *dns_over_tls_mode_str;
        char *llmnr_mode_str;
        char *mdns_mode_str;
        char **negative_trust_anchors;
        char *resolv_conf_mode_str;
        char *delegate;
        bool dnssec_supported;
} DNSConfiguration;

DNSConfiguration* dns_configuration_free(DNSConfiguration *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSConfiguration*, dns_configuration_free);

int dns_configuration_from_json(sd_json_variant *variant, DNSConfiguration **ret);
bool dns_is_accessible(DNSConfiguration *c);
bool dns_configuration_contains_search_domain(DNSConfiguration *c, const char *domain);

extern const struct hash_ops dns_configuration_hash_ops;
