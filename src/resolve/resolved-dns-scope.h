/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "ratelimit.h"

typedef struct DnsQueryCandidate DnsQueryCandidate;
typedef struct DnsScope DnsScope;

#include "resolved-dns-cache.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-query.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-zone.h"

typedef enum DnsScopeMatch {
        DNS_SCOPE_NO,
        DNS_SCOPE_LAST_RESORT,
        DNS_SCOPE_MAYBE,
        DNS_SCOPE_YES_BASE, /* Add the number of matching labels to this */
        DNS_SCOPE_YES_END = DNS_SCOPE_YES_BASE + DNS_N_LABELS_MAX,
        _DNS_SCOPE_MATCH_MAX,
        _DNS_SCOPE_MATCH_INVALID = -EINVAL,
} DnsScopeMatch;

struct DnsScope {
        Manager *manager;

        DnsProtocol protocol;
        int family;

        /* Copied at scope creation time from the link/manager */
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;

        Link *link;

        DnsCache cache;
        DnsZone zone;

        OrderedHashmap *conflict_queue;
        sd_event_source *conflict_event_source;

        sd_event_source *announce_event_source;

        sd_event_source *mdns_goodbye_event_source;

        RateLimit ratelimit;

        usec_t resend_timeout;
        usec_t max_rtt;

        LIST_HEAD(DnsQueryCandidate, query_candidates);

        /* Note that we keep track of ongoing transactions in two ways: once in a hashmap, indexed by the rr
         * key, and once in a linked list. We use the hashmap to quickly find transactions we can reuse for a
         * key. But note that there might be multiple transactions for the same key (because the associated
         * query flags might differ in incompatible ways: e.g. we may not reuse a non-validating transaction
         * as validating. Hence we maintain a per-key list of transactions, which we iterate through to find
         * one we can reuse with matching flags. */
        Hashmap *transactions_by_key;
        LIST_HEAD(DnsTransaction, transactions);

        LIST_FIELDS(DnsScope, scopes);

        bool announced;
};

int dns_scope_new(Manager *m, DnsScope **ret, Link *l, DnsProtocol p, int family);
DnsScope* dns_scope_free(DnsScope *s);

void dns_scope_packet_received(DnsScope *s, usec_t rtt);
void dns_scope_packet_lost(DnsScope *s, usec_t usec);

int dns_scope_emit_udp(DnsScope *s, int fd, int af, DnsPacket *p);
int dns_scope_socket_tcp(DnsScope *s, int family, const union in_addr_union *address, DnsServer *server, uint16_t port, union sockaddr_union *ret_socket_address);
int dns_scope_socket_udp(DnsScope *s, DnsServer *server);

DnsScopeMatch dns_scope_good_domain(DnsScope *s, DnsQuery *q, uint64_t query_flags);
bool dns_scope_good_key(DnsScope *s, const DnsResourceKey *key);

DnsServer *dns_scope_get_dns_server(DnsScope *s);
unsigned dns_scope_get_n_dns_servers(DnsScope *s);
void dns_scope_next_dns_server(DnsScope *s, DnsServer *if_current);

int dns_scope_llmnr_membership(DnsScope *s, bool b);
int dns_scope_mdns_membership(DnsScope *s, bool b);

int dns_scope_make_reply_packet(DnsScope *s, uint16_t id, int rcode, DnsQuestion *q, DnsAnswer *answer, DnsAnswer *soa, bool tentative, DnsPacket **ret);
void dns_scope_process_query(DnsScope *s, DnsStream *stream, DnsPacket *p);

DnsTransaction *dns_scope_find_transaction(DnsScope *scope, DnsResourceKey *key, uint64_t query_flags);

int dns_scope_notify_conflict(DnsScope *scope, DnsResourceRecord *rr);
void dns_scope_check_conflicts(DnsScope *scope, DnsPacket *p);

void dns_scope_dump(DnsScope *s, FILE *f);

DnsSearchDomain *dns_scope_get_search_domains(DnsScope *s);

bool dns_scope_name_wants_search_domain(DnsScope *s, const char *name);

bool dns_scope_network_good(DnsScope *s);

int dns_scope_ifindex(DnsScope *s);
const char* dns_scope_ifname(DnsScope *s);

int dns_scope_announce(DnsScope *scope, bool goodbye);

int dns_scope_add_dnssd_services(DnsScope *scope);
int dns_scope_remove_dnssd_services(DnsScope *scope);

bool dns_scope_is_default_route(DnsScope *scope);

int dns_scope_dump_cache_to_json(DnsScope *scope, sd_json_variant **ret);

int dns_type_suitable_for_protocol(uint16_t type, DnsProtocol protocol);
int dns_question_types_suitable_for_protocol(DnsQuestion *q, DnsProtocol protocol);
