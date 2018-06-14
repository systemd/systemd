/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "set.h"

typedef struct DnsQueryCandidate DnsQueryCandidate;
typedef struct DnsQuery DnsQuery;

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-search-domain.h"

struct DnsQueryCandidate {
        DnsQuery *query;
        DnsScope *scope;

        DnsSearchDomain *search_domain;

        int error_code;
        Set *transactions;

        LIST_FIELDS(DnsQueryCandidate, candidates_by_query);
        LIST_FIELDS(DnsQueryCandidate, candidates_by_scope);
};

struct DnsQuery {
        Manager *manager;

        /* When resolving a service, we first create a TXT+SRV query,
         * and then for the hostnames we discover auxiliary A+AAAA
         * queries. This pointer always points from the auxiliary
         * queries back to the TXT+SRV query. */
        DnsQuery *auxiliary_for;
        LIST_HEAD(DnsQuery, auxiliary_queries);
        unsigned n_auxiliary_queries;
        int auxiliary_result;

        /* The question, formatted in IDNA for use on classic DNS, and as UTF8 for use in LLMNR or mDNS. Note that even
         * on classic DNS some labels might use UTF8 encoding. Specifically, DNS-SD service names (in contrast to their
         * domain suffixes) use UTF-8 encoding even on DNS. Thus, the difference between these two fields is mostly
         * relevant only for explicit *hostname* lookups as well as the domain suffixes of service lookups. */
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;

        uint64_t flags;
        int ifindex;

        /* If true, A or AAAA RR lookups will be suppressed on links with no routable address of the matching address
         * family */
        bool suppress_unroutable_family;

        /* If true, the RR TTLs of the answer will be clamped by their current left validity in the cache */
        bool clamp_ttl;

        DnsTransactionState state;
        unsigned n_cname_redirects;

        LIST_HEAD(DnsQueryCandidate, candidates);
        sd_event_source *timeout_event_source;

        /* Discovered data */
        DnsAnswer *answer;
        int answer_rcode;
        DnssecResult answer_dnssec_result;
        bool answer_authenticated;
        DnsProtocol answer_protocol;
        int answer_family;
        DnsSearchDomain *answer_search_domain;
        int answer_errno; /* if state is DNS_TRANSACTION_ERRNO */
        bool previous_redirect_unauthenticated;

        /* Bus client information */
        sd_bus_message *request;
        int request_family;
        bool request_address_valid;
        union in_addr_union request_address;
        unsigned block_all_complete;
        char *request_address_string;

        /* DNS stub information */
        DnsPacket *request_dns_packet;
        DnsStream *request_dns_stream;
        DnsPacket *reply_dns_packet;

        /* Completion callback */
        void (*complete)(DnsQuery* q);
        unsigned block_ready;

        sd_bus_track *bus_track;

        LIST_FIELDS(DnsQuery, queries);
        LIST_FIELDS(DnsQuery, auxiliary_queries);
};

enum {
        DNS_QUERY_MATCH,
        DNS_QUERY_NOMATCH,
        DNS_QUERY_RESTARTED,
};

DnsQueryCandidate* dns_query_candidate_free(DnsQueryCandidate *c);
void dns_query_candidate_notify(DnsQueryCandidate *c);

int dns_query_new(Manager *m, DnsQuery **q, DnsQuestion *question_utf8, DnsQuestion *question_idna, int family, uint64_t flags);
DnsQuery *dns_query_free(DnsQuery *q);

int dns_query_make_auxiliary(DnsQuery *q, DnsQuery *auxiliary_for);

int dns_query_go(DnsQuery *q);
void dns_query_ready(DnsQuery *q);

int dns_query_process_cname(DnsQuery *q);

int dns_query_bus_track(DnsQuery *q, sd_bus_message *m);

DnsQuestion* dns_query_question_for_protocol(DnsQuery *q, DnsProtocol protocol);

const char *dns_query_string(DnsQuery *q);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);

bool dns_query_fully_authenticated(DnsQuery *q);
