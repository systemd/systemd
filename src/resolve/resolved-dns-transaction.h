/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "resolved-def.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-server.h"
#include "resolved-forward.h"

typedef enum DnsTransactionState {
        DNS_TRANSACTION_NULL,
        DNS_TRANSACTION_PENDING,
        DNS_TRANSACTION_VALIDATING,
        DNS_TRANSACTION_RCODE_FAILURE,
        DNS_TRANSACTION_SUCCESS,
        DNS_TRANSACTION_NO_SERVERS,
        DNS_TRANSACTION_TIMEOUT,
        DNS_TRANSACTION_ATTEMPTS_MAX_REACHED,
        DNS_TRANSACTION_INVALID_REPLY,
        DNS_TRANSACTION_ERRNO,
        DNS_TRANSACTION_ABORTED,
        DNS_TRANSACTION_DNSSEC_FAILED,
        DNS_TRANSACTION_NO_TRUST_ANCHOR,
        DNS_TRANSACTION_RR_TYPE_UNSUPPORTED,
        DNS_TRANSACTION_NETWORK_DOWN,
        DNS_TRANSACTION_NOT_FOUND, /* like NXDOMAIN, but when LLMNR/TCP connections fail */
        DNS_TRANSACTION_NO_SOURCE, /* All suitable DnsTransactionSource turned off */
        DNS_TRANSACTION_STUB_LOOP,
        _DNS_TRANSACTION_STATE_MAX,
        _DNS_TRANSACTION_STATE_INVALID = -EINVAL,
} DnsTransactionState;

#define DNS_TRANSACTION_IS_LIVE(state) IN_SET((state), DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_VALIDATING)

typedef enum DnsTransactionSource {
        DNS_TRANSACTION_NETWORK,
        DNS_TRANSACTION_CACHE,
        DNS_TRANSACTION_ZONE,
        DNS_TRANSACTION_TRUST_ANCHOR,
        _DNS_TRANSACTION_SOURCE_MAX,
        _DNS_TRANSACTION_SOURCE_INVALID = -EINVAL,
} DnsTransactionSource;

typedef struct DnsTransaction {
        /* Pointers and 8-byte types */
        DnsScope *scope;
        DnsResourceKey *key;         /* For regular lookups the RR key to look for */
        DnsPacket *bypass;           /* For bypass lookups the full original request packet */
        uint64_t query_flags;
        DnsPacket *sent, *received;
        DnsAnswer *answer;
        char *answer_ede_msg;
        uint64_t answer_query_flags;
        DnsAnswer *validated_keys;
        usec_t start_usec;
        usec_t next_attempt_after;
        sd_event_source *timeout_event_source;
        sd_event_source *dns_udp_event_source;
        DnsStream *stream;
        DnsServer *server;
        Set *notify_query_candidates, *notify_query_candidates_done;
        Set *notify_zone_items, *notify_zone_items_done;
        Set *notify_transactions, *notify_transactions_done;
        Set *dnssec_transactions;
        LIST_FIELDS(DnsTransaction, transactions_by_scope);
        LIST_FIELDS(DnsTransaction, transactions_by_stream);
        LIST_FIELDS(DnsTransaction, transactions_by_key);

        /* Enums and 32-bit integers */
        int answer_rcode;
        int answer_ede_rcode;
        DnssecResult answer_dnssec_result;
        DnsTransactionSource answer_source;
        uint32_t answer_nsec_ttl;
        int answer_errno; /* if state is DNS_TRANSACTION_ERRNO */
        DnsTransactionState state;
        unsigned n_attempts;
        int dns_udp_fd;
        DnsServerFeatureLevel current_feature_level;
        DnsServerFeatureLevel clamp_feature_level_servfail;
        unsigned n_picked_servers;
        unsigned block_gc;

        /* 16-bit integers */
        uint16_t id;

        /* Booleans */
        bool tried_stream:1;
        bool initial_jitter_scheduled:1;
        bool initial_jitter_elapsed:1;
        bool probing:1;
        bool seen_timeout:1;
        bool wait_for_answer:1;

        /* Note: fields should be ordered to minimize alignment gaps. Use pahole! */
} DnsTransaction;

int dns_transaction_new(DnsTransaction **ret, DnsScope *s, DnsResourceKey *key, DnsPacket *bypass, uint64_t flags);
DnsTransaction* dns_transaction_free(DnsTransaction *t);

DnsTransaction* dns_transaction_gc(DnsTransaction *t);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsTransaction*, dns_transaction_gc);

int dns_transaction_go(DnsTransaction *t);

void dns_transaction_process_reply(DnsTransaction *t, DnsPacket *p, bool encrypted);
void dns_transaction_complete(DnsTransaction *t, DnsTransactionState state);

void dns_transaction_notify(DnsTransaction *t, DnsTransaction *source);
int dns_transaction_validate_dnssec(DnsTransaction *t);
int dns_transaction_request_dnssec_keys(DnsTransaction *t);

DnsResourceKey* dns_transaction_key(DnsTransaction *t);

static inline uint64_t dns_transaction_source_to_query_flags(DnsTransactionSource s) {

        switch (s) {

        case DNS_TRANSACTION_NETWORK:
                return SD_RESOLVED_FROM_NETWORK;

        case DNS_TRANSACTION_CACHE:
                return SD_RESOLVED_FROM_CACHE;

        case DNS_TRANSACTION_ZONE:
                return SD_RESOLVED_FROM_ZONE;

        case DNS_TRANSACTION_TRUST_ANCHOR:
                return SD_RESOLVED_FROM_TRUST_ANCHOR;

        default:
                return 0;
        }
}

const char* dns_transaction_state_to_string(DnsTransactionState p) _const_;
DnsTransactionState dns_transaction_state_from_string(const char *s) _pure_;

const char* dns_transaction_source_to_string(DnsTransactionSource p) _const_;
DnsTransactionSource dns_transaction_source_from_string(const char *s) _pure_;
