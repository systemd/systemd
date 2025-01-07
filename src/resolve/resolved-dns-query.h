/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-varlink.h"

#include "set.h"

typedef struct DnsQueryCandidate DnsQueryCandidate;
typedef struct DnsQuery DnsQuery;
typedef struct DnsStubListenerExtra DnsStubListenerExtra;

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-transaction.h"

struct DnsQueryCandidate {
        unsigned n_ref;
        int error_code;

        DnsQuery *query;
        DnsScope *scope;

        DnsSearchDomain *search_domain;

        Set *transactions;
        sd_event_source *timeout_event_source;

        LIST_FIELDS(DnsQueryCandidate, candidates_by_query);
        LIST_FIELDS(DnsQueryCandidate, candidates_by_scope);
};

struct DnsQuery {
        Manager *manager;

        /* The question, formatted in IDNA for use on classic DNS, and as UTF8 for use in LLMNR or mDNS. Note
         * that even on classic DNS some labels might use UTF8 encoding. Specifically, DNS-SD service names
         * (in contrast to their domain suffixes) use UTF-8 encoding even on DNS. Thus, the difference
         * between these two fields is mostly relevant only for explicit *hostname* lookups as well as the
         * domain suffixes of service lookups.
         *
         * Note that questions may consist of multiple RR keys at once, but they must be for the same domain
         * name. This is used for A+AAAA and TXT+SRV lookups: we'll allocate a single DnsQuery object for
         * them instead of two separate ones. That allows us minor optimizations with response handling:
         * CNAME/DNAMEs of the first reply we get can already be used to follow the CNAME/DNAME chain for
         * both, and we can take benefit of server replies that oftentimes put A responses into AAAA queries
         * and vice versa (in the additional section). */
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;

        /* If this is not a question by ourselves, but a "bypass" request, we propagate the original packet
         * here, and use that instead. */
        DnsPacket *question_bypass;

        /* When we follow a CNAME redirect, we save the original question here, for informational/monitoring
         * purposes. We'll keep adding to this whenever we go one step in the redirect, so that in the end
         * this will contain the complete set of CNAME questions. */
        DnsQuestion *collected_questions;

        uint64_t flags;
        int ifindex;

        /* When resolving a service, we first create a TXT+SRV query, and then for the hostnames we discover
         * auxiliary A+AAAA queries. This pointer always points from the auxiliary queries back to the
         * TXT+SRV query. */
        int auxiliary_result;
        DnsQuery *auxiliary_for;
        LIST_HEAD(DnsQuery, auxiliary_queries);

        LIST_HEAD(DnsQueryCandidate, candidates);
        sd_event_source *timeout_event_source;

        /* Discovered data */
        DnsAnswer *answer;
        int answer_rcode;
        int answer_ede_rcode;
        char *answer_ede_msg;
        DnssecResult answer_dnssec_result;
        uint64_t answer_query_flags;
        DnsProtocol answer_protocol;
        int answer_family;
        DnsPacket *answer_full_packet;
        DnsSearchDomain *answer_search_domain;

        DnsTransactionState state;
        int answer_errno; /* if state is DNS_TRANSACTION_ERRNO */

        unsigned block_ready;

        uint8_t n_auxiliary_queries;
        uint8_t n_cname_redirects;

        bool previous_redirect_unauthenticated:1;
        bool previous_redirect_non_confidential:1;
        bool previous_redirect_non_synthetic:1;
        bool request_address_valid:1;

        /* Bus + Varlink client information */
        sd_bus_message *bus_request;
        sd_varlink *varlink_request;
        int request_family;
        union in_addr_union request_address;
        unsigned block_all_complete;
        char *request_address_string;

        /* DNS stub information */
        DnsPacket *request_packet;
        DnsStream *request_stream;
        DnsAnswer *reply_answer;
        DnsAnswer *reply_authoritative;
        DnsAnswer *reply_additional;
        DnsStubListenerExtra *stub_listener_extra;

        /* Completion callback */
        void (*complete)(DnsQuery* q);

        sd_bus_track *bus_track;

        LIST_FIELDS(DnsQuery, queries);
        LIST_FIELDS(DnsQuery, auxiliary_queries);

        /* Note: fields should be ordered to minimize alignment gaps. Use pahole! */
};

enum {
        DNS_QUERY_MATCH,
        DNS_QUERY_NOMATCH,
        DNS_QUERY_CNAME,
};

DnsQueryCandidate* dns_query_candidate_ref(DnsQueryCandidate*);
DnsQueryCandidate* dns_query_candidate_unref(DnsQueryCandidate*);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQueryCandidate*, dns_query_candidate_unref);

void dns_query_candidate_notify(DnsQueryCandidate *c);

int dns_query_new(Manager *m, DnsQuery **q, DnsQuestion *question_utf8, DnsQuestion *question_idna, DnsPacket *question_bypass, int family, uint64_t flags);
DnsQuery *dns_query_free(DnsQuery *q);

int dns_query_make_auxiliary(DnsQuery *q, DnsQuery *auxiliary_for);

int dns_query_go(DnsQuery *q);
void dns_query_ready(DnsQuery *q);

int dns_query_process_cname_one(DnsQuery *q);
int dns_query_process_cname_many(DnsQuery *q);

void dns_query_complete(DnsQuery *q, DnsTransactionState state);

DnsQuestion* dns_query_question_for_protocol(DnsQuery *q, DnsProtocol protocol);

const char* dns_query_string(DnsQuery *q);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);

bool dns_query_fully_authenticated(DnsQuery *q);
bool dns_query_fully_confidential(DnsQuery *q);
bool dns_query_fully_authoritative(DnsQuery *q);

static inline uint64_t dns_query_reply_flags_make(DnsQuery *q) {
        assert(q);

        return SD_RESOLVED_FLAGS_MAKE(q->answer_protocol,
                                      q->answer_family,
                                      dns_query_fully_authenticated(q),
                                      dns_query_fully_confidential(q)) |
                (q->answer_query_flags & (SD_RESOLVED_FROM_MASK|SD_RESOLVED_SYNTHETIC));
}
