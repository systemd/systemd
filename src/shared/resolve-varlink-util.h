/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"
#include "in-addr-util.h"

typedef struct ResolveError {
        int rcode;
        int ede_rcode;
        char *ede_msg;
        char *query_string;
        char *result;
} ResolveError;

void resolve_error_done(ResolveError *error);

int dispatch_resolve_error(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedAddress {
        int ifindex;
        int family;
        struct in_addr_data in_addr;
} ResolvedAddress;

typedef struct ResolveHostnameReply {
        char *name;
        uint64_t flags;
        ResolvedAddress *addresses;
        size_t n_addresses;
} ResolveHostnameReply;

void resolve_hostname_reply_done(ResolveHostnameReply *reply);

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedName {
        int ifindex;
        char *name;
} ResolvedName;

typedef struct ResolveAddressReply {
        uint64_t flags;
        ResolvedName *names;
        size_t n_names;
} ResolveAddressReply;

void resolve_address_reply_done(ResolveAddressReply *reply);

int dispatch_resolve_address_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedRecord {
        int ifindex;
        struct iovec raw;
} ResolvedRecord;

typedef struct ResolveRecordReply {
        uint64_t flags;
        ResolvedRecord *records;
        size_t n_records;
} ResolveRecordReply;

void resolve_record_reply_done(ResolveRecordReply *reply);

int dispatch_resolve_record_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedService {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char *hostname;
        char *canonical_name;
        ResolvedAddress *addresses;
        size_t n_addresses;
} ResolvedService;

typedef struct ResolvedCanonical {
        char *name;
        char *type;
        char *domain;
} ResolvedCanonical;

typedef struct ResolveServiceReply {
        ResolvedService *services;
        size_t n_services;
        char **txt;
        ResolvedCanonical canonical;
        uint64_t flags;
} ResolveServiceReply;

void resolve_service_reply_done(ResolveServiceReply *reply);

int dispatch_resolve_service_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct DNSServer {
        struct in_addr_data in_addr;
        int family;
        uint16_t port;
        int ifindex;
        char *server_name;
        bool accessible;
} DNSServer;

DNSServer* dns_server_free(DNSServer *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSServer*, dns_server_free);

typedef struct SearchDomain {
        char *name;
        bool route_only;
        int ifindex;
} SearchDomain;

SearchDomain* search_domain_free(SearchDomain *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(SearchDomain*, search_domain_free);

typedef struct DNSScope {
        char *ifname;
        int ifindex;
        char *protocol;
        int family;
        char *dnssec_mode_str;
        char *dns_over_tls_mode_str;
} DNSScope;

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
