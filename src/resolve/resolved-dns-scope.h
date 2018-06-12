/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "list.h"

typedef struct DnsScope DnsScope;

#include "resolved-dns-cache.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-query.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-zone.h"
#include "resolved-link.h"

typedef enum DnsScopeMatch {
        DNS_SCOPE_NO,
        DNS_SCOPE_MAYBE,
        DNS_SCOPE_YES,
        _DNS_SCOPE_MATCH_MAX,
        _DNS_SCOPE_INVALID = -1
} DnsScopeMatch;

struct DnsScope {
        Manager *manager;

        DnsProtocol protocol;
        int family;
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;

        Link *link;

        DnsCache cache;
        DnsZone zone;

        OrderedHashmap *conflict_queue;
        sd_event_source *conflict_event_source;

        bool announced:1;
        sd_event_source *announce_event_source;

        RateLimit ratelimit;

        usec_t resend_timeout;
        usec_t max_rtt;

        LIST_HEAD(DnsQueryCandidate, query_candidates);

        /* Note that we keep track of ongoing transactions in two
         * ways: once in a hashmap, indexed by the rr key, and once in
         * a linked list. We use the hashmap to quickly find
         * transactions we can reuse for a key. But note that there
         * might be multiple transactions for the same key (because
         * the zone probing can't reuse a transaction answered from
         * the zone or the cache), and the hashmap only tracks the
         * most recent entry. */
        Hashmap *transactions_by_key;
        LIST_HEAD(DnsTransaction, transactions);

        LIST_FIELDS(DnsScope, scopes);
};

int dns_scope_new(Manager *m, DnsScope **ret, Link *l, DnsProtocol p, int family);
DnsScope* dns_scope_free(DnsScope *s);

void dns_scope_packet_received(DnsScope *s, usec_t rtt);
void dns_scope_packet_lost(DnsScope *s, usec_t usec);

int dns_scope_emit_udp(DnsScope *s, int fd, DnsPacket *p);
int dns_scope_socket_tcp(DnsScope *s, int family, const union in_addr_union *address, DnsServer *server, uint16_t port, union sockaddr_union *ret_socket_address);
int dns_scope_socket_udp(DnsScope *s, DnsServer *server, uint16_t port);

DnsScopeMatch dns_scope_good_domain(DnsScope *s, int ifindex, uint64_t flags, const char *domain);
bool dns_scope_good_key(DnsScope *s, const DnsResourceKey *key);

DnsServer *dns_scope_get_dns_server(DnsScope *s);
unsigned dns_scope_get_n_dns_servers(DnsScope *s);
void dns_scope_next_dns_server(DnsScope *s);

int dns_scope_llmnr_membership(DnsScope *s, bool b);
int dns_scope_mdns_membership(DnsScope *s, bool b);

int dns_scope_make_reply_packet(DnsScope *s, uint16_t id, int rcode, DnsQuestion *q, DnsAnswer *answer, DnsAnswer *soa, bool tentative, DnsPacket **ret);
void dns_scope_process_query(DnsScope *s, DnsStream *stream, DnsPacket *p);

DnsTransaction *dns_scope_find_transaction(DnsScope *scope, DnsResourceKey *key, bool cache_ok);

int dns_scope_notify_conflict(DnsScope *scope, DnsResourceRecord *rr);
void dns_scope_check_conflicts(DnsScope *scope, DnsPacket *p);

void dns_scope_dump(DnsScope *s, FILE *f);

DnsSearchDomain *dns_scope_get_search_domains(DnsScope *s);

bool dns_scope_name_needs_search_domain(DnsScope *s, const char *name);

bool dns_scope_network_good(DnsScope *s);

int dns_scope_ifindex(DnsScope *s);

int dns_scope_announce(DnsScope *scope, bool goodbye);

int dns_scope_add_dnssd_services(DnsScope *scope);

int dns_scope_remove_dnssd_services(DnsScope *scope);
