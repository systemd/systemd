/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct DnsTransaction DnsTransaction;
typedef enum DnsTransactionState DnsTransactionState;
typedef enum DnsTransactionSource DnsTransactionSource;

enum DnsTransactionState {
        DNS_TRANSACTION_NULL,
        DNS_TRANSACTION_PENDING,
        DNS_TRANSACTION_VALIDATING,
        DNS_TRANSACTION_FAILURE,
        DNS_TRANSACTION_SUCCESS,
        DNS_TRANSACTION_NO_SERVERS,
        DNS_TRANSACTION_TIMEOUT,
        DNS_TRANSACTION_ATTEMPTS_MAX_REACHED,
        DNS_TRANSACTION_INVALID_REPLY,
        DNS_TRANSACTION_RESOURCES,
        DNS_TRANSACTION_ABORTED,
        DNS_TRANSACTION_DNSSEC_FAILED,
        _DNS_TRANSACTION_STATE_MAX,
        _DNS_TRANSACTION_STATE_INVALID = -1
};

#define DNS_TRANSACTION_IS_LIVE(state) IN_SET((state), DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_VALIDATING)

enum DnsTransactionSource {
        DNS_TRANSACTION_NETWORK,
        DNS_TRANSACTION_CACHE,
        DNS_TRANSACTION_ZONE,
        DNS_TRANSACTION_TRUST_ANCHOR,
        _DNS_TRANSACTION_SOURCE_MAX,
        _DNS_TRANSACTION_SOURCE_INVALID = -1
};

#include "resolved-dns-answer.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-question.h"
#include "resolved-dns-scope.h"

struct DnsTransaction {
        DnsScope *scope;

        DnsResourceKey *key;

        DnsTransactionState state;
        DnssecResult dnssec_result;

        uint16_t id;

        bool initial_jitter_scheduled;
        bool initial_jitter_elapsed;

        DnsPacket *sent, *received;

        DnsAnswer *answer;
        int answer_rcode;
        DnsTransactionSource answer_source;
        bool answer_authenticated;

        /* Contains DS and DNSKEY RRs we already verified and need to authenticate this reply */
        DnsAnswer *validated_keys;

        usec_t start_usec;
        usec_t next_attempt_after;
        sd_event_source *timeout_event_source;
        unsigned n_attempts;

        int dns_udp_fd;
        sd_event_source *dns_udp_event_source;

        /* The active server */
        DnsServer *server;

        /* The features of the DNS server at time of transaction start */
        DnsServerFeatureLevel current_features;

        /* TCP connection logic, if we need it */
        DnsStream *stream;

        /* Query candidates this transaction is referenced by and that
         * shall be notified about this specific transaction
         * completing. */
        Set *notify_query_candidates;

        /* Zone items this transaction is referenced by and that shall
         * be notified about completion. */
        Set *notify_zone_items;

        /* Other transactions that this transactions is referenced by
         * and that shall be notified about completion. This is used
         * when transactions want to validate their RRsets, but need
         * another DNSKEY or DS RR to do so. */
        Set *notify_transactions;

        /* The opposite direction: the transactions this transaction
         * created in order to request DNSKEY or DS RRs. */
        Set *dnssec_transactions;

        unsigned block_gc;

        LIST_FIELDS(DnsTransaction, transactions_by_scope);
};

int dns_transaction_new(DnsTransaction **ret, DnsScope *s, DnsResourceKey *key);
DnsTransaction* dns_transaction_free(DnsTransaction *t);

void dns_transaction_gc(DnsTransaction *t);
int dns_transaction_go(DnsTransaction *t);

void dns_transaction_process_reply(DnsTransaction *t, DnsPacket *p);
void dns_transaction_complete(DnsTransaction *t, DnsTransactionState state);

void dns_transaction_notify(DnsTransaction *t, DnsTransaction *source);
int dns_transaction_validate_dnssec(DnsTransaction *t);
int dns_transaction_request_dnssec_keys(DnsTransaction *t);

const char* dns_transaction_state_to_string(DnsTransactionState p) _const_;
DnsTransactionState dns_transaction_state_from_string(const char *s) _pure_;

const char* dns_transaction_source_to_string(DnsTransactionSource p) _const_;
DnsTransactionSource dns_transaction_source_from_string(const char *s) _pure_;

/* LLMNR Jitter interval, see RFC 4795 Section 7 */
#define LLMNR_JITTER_INTERVAL_USEC (100 * USEC_PER_MSEC)

/* mDNS Jitter interval, see RFC 6762 Section 5.2 */
#define MDNS_JITTER_MIN_USEC   (20 * USEC_PER_MSEC)
#define MDNS_JITTER_RANGE_USEC (100 * USEC_PER_MSEC)

/* Maximum attempts to send DNS requests, across all DNS servers */
#define DNS_TRANSACTION_ATTEMPTS_MAX 16

/* Maximum attempts to send LLMNR requests, see RFC 4795 Section 2.7 */
#define LLMNR_TRANSACTION_ATTEMPTS_MAX 3

#define TRANSACTION_ATTEMPTS_MAX(p) ((p) == DNS_PROTOCOL_LLMNR ? LLMNR_TRANSACTION_ATTEMPTS_MAX : DNS_TRANSACTION_ATTEMPTS_MAX)
