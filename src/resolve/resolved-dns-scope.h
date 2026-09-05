/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dns-def.h"
#include "dns-packet.h"
#include "list.h"
#include "ratelimit.h"
#include "resolve-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-zone.h"
#include "resolved-forward.h"

typedef enum DnsScopeMatch {
        DNS_SCOPE_NO,
        DNS_SCOPE_LAST_RESORT,
        DNS_SCOPE_MAYBE,
        DNS_SCOPE_YES_BASE, /* Add the number of matching labels to this */
        DNS_SCOPE_YES_END = DNS_SCOPE_YES_BASE + DNS_N_LABELS_MAX,
        _DNS_SCOPE_MATCH_MAX,
        _DNS_SCOPE_MATCH_INVALID = -EINVAL,
} DnsScopeMatch;

typedef enum DnsScopeOrigin {
        DNS_SCOPE_GLOBAL,
        DNS_SCOPE_LINK,
        DNS_SCOPE_DELEGATE,
        _DNS_SCOPE_ORIGIN_MAX,
        _DNS_SCOPE_ORIGIN_INVALID = -EINVAL,
} DnsScopeOrigin;

typedef struct DnsScope {
        Manager *manager;

        DnsScopeOrigin origin;

        DnsProtocol protocol;
        int family;

        /* Copied at scope creation time from the link/manager */
        DnssecMode dnssec_mode;
        DnsOverTlsMode dns_over_tls_mode;

        Link *link;
        DnsDelegate *delegate;

        DnsCache cache;
        DnsZone zone;

        OrderedHashmap *conflict_queue;
        sd_event_source *conflict_event_source;

        sd_event_source *announce_event_source;

        /* Runtime withdrawals emitted on this scope, awaiting their RFC 6762 §8.3 one-second
         * retransmission. A scope freed inside that window abandons them, see dns_scope_free(). */
        DnsAnswer *pending_withdrawals;

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
} DnsScope;

int dns_scope_new(Manager *m, DnsScope **ret, DnsScopeOrigin origin, Link *link, DnsDelegate *delegate, DnsProtocol protocol, int family);
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

bool dns_scope_mdns_withdrawing(DnsScope *scope);
bool dns_scope_network_good(DnsScope *s);

int dns_scope_ifindex(DnsScope *s);

/* The first mDNS scope at or after 's' in the manager's scope list, NULL if there is none. */
DnsScope* dns_scope_first_mdns(DnsScope *s);

/* Walk the mDNS scopes in a scope list — pass the manager's, which already holds both families of
 * every link, and this replaces walking the links and spelling out the two scope fields, along with
 * every caller's skip of the ones a link does not have. Takes the list head rather than the manager
 * so that this header needs no more than the DnsScope definition. Not safe against the body freeing
 * the scope it was handed. */
#define FOREACH_MDNS_SCOPE(scope, head)                                 \
        for (DnsScope *scope = dns_scope_first_mdns(head);              \
             scope;                                                     \
             scope = dns_scope_first_mdns(scope->scopes_next))

const char* dns_scope_ifname(DnsScope *s);

bool dns_scope_shutdown_goodbye_has_content(DnsScope *scope);
int dns_scope_withdraw_rrs(DnsScope *scope, DnsAnswer *candidates);
void dns_scope_flush_pending_withdrawals(DnsScope *scope);
int dns_scope_announce(DnsScope *scope, bool goodbye);
/* Is this record one of the host's own (an address record or its reverse mapping) on this scope?
 * Those are the records the shutdown goodbyes deliberately keep, so they are still ours to answer
 * for while the withdrawal of everything else stands. */
bool dns_scope_rr_is_host_record(DnsScope *scope, DnsResourceRecord *rr);

int dns_scope_add_dnssd_registered_services(DnsScope *scope);
int dns_scope_remove_dnssd_registered_services(DnsScope *scope);

bool dns_scope_is_default_route(DnsScope *scope);

int dns_scope_to_json(DnsScope *scope, bool with_cache, sd_json_variant **ret);

int dns_type_suitable_for_protocol(uint16_t type, DnsProtocol protocol);
int dns_question_types_suitable_for_protocol(DnsQuestion *q, DnsProtocol protocol);

DECLARE_STRING_TABLE_LOOKUP(dns_scope_origin, DnsScopeOrigin);
