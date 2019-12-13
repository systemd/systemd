/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "in-addr-util.h"
#include "ratelimit.h"
#include "resolve-util.h"

typedef struct Link Link;
typedef struct LinkAddress LinkAddress;

#include "resolved-dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-manager.h"

#define LINK_SEARCH_DOMAINS_MAX 256
#define LINK_DNS_SERVERS_MAX 256

struct LinkAddress {
        Link *link;

        int family;
        union in_addr_union in_addr;

        unsigned char flags, scope;

        DnsResourceRecord *llmnr_address_rr;
        DnsResourceRecord *llmnr_ptr_rr;
        DnsResourceRecord *mdns_address_rr;
        DnsResourceRecord *mdns_ptr_rr;

        LIST_FIELDS(LinkAddress, addresses);
};

struct Link {
        Manager *manager;

        int ifindex;
        unsigned flags;

        LIST_HEAD(LinkAddress, addresses);
        unsigned n_addresses;

        LIST_HEAD(DnsServer, dns_servers);
        DnsServer *current_dns_server;
        unsigned n_dns_servers;

        LIST_HEAD(DnsSearchDomain, search_domains);
        unsigned n_search_domains;

        int default_route;

        ResolveSupport llmnr_support;
        ResolveSupport mdns_support;
        DnsOverTlsMode dns_over_tls_mode;
        DnssecMode dnssec_mode;
        Set *dnssec_negative_trust_anchors;

        DnsScope *unicast_scope;
        DnsScope *llmnr_ipv4_scope;
        DnsScope *llmnr_ipv6_scope;
        DnsScope *mdns_ipv4_scope;
        DnsScope *mdns_ipv6_scope;

        bool is_managed;

        char *ifname;
        uint32_t mtu;
        uint8_t operstate;

        bool loaded;
        char *state_file;

        bool unicast_relevant;
};

int link_new(Manager *m, Link **ret, int ifindex);
Link *link_free(Link *l);
int link_process_rtnl(Link *l, sd_netlink_message *m);
int link_update(Link *l);
bool link_relevant(Link *l, int family, bool local_multicast);
LinkAddress* link_find_address(Link *l, int family, const union in_addr_union *in_addr);
void link_add_rrs(Link *l, bool force_remove);

void link_flush_settings(Link *l);
void link_set_dnssec_mode(Link *l, DnssecMode mode);
void link_set_dns_over_tls_mode(Link *l, DnsOverTlsMode mode);
void link_allocate_scopes(Link *l);

DnsServer* link_set_dns_server(Link *l, DnsServer *s);
DnsServer* link_get_dns_server(Link *l);
void link_next_dns_server(Link *l);

DnssecMode link_get_dnssec_mode(Link *l);
bool link_dnssec_supported(Link *l);

DnsOverTlsMode link_get_dns_over_tls_mode(Link *l);

int link_save_user(Link *l);
int link_load_user(Link *l);
void link_remove_user(Link *l);

int link_address_new(Link *l, LinkAddress **ret, int family, const union in_addr_union *in_addr);
LinkAddress *link_address_free(LinkAddress *a);
int link_address_update_rtnl(LinkAddress *a, sd_netlink_message *m);
bool link_address_relevant(LinkAddress *l, bool local_multicast);
void link_address_add_rrs(LinkAddress *a, bool force_remove);

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
