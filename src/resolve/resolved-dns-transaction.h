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

enum DnsTransactionState {
        DNS_TRANSACTION_NULL,
        DNS_TRANSACTION_PENDING,
        DNS_TRANSACTION_FAILURE,
        DNS_TRANSACTION_SUCCESS,
        DNS_TRANSACTION_NO_SERVERS,
        DNS_TRANSACTION_TIMEOUT,
        DNS_TRANSACTION_ATTEMPTS_MAX_REACHED,
        DNS_TRANSACTION_INVALID_REPLY,
        DNS_TRANSACTION_RESOURCES,
        DNS_TRANSACTION_ABORTED,
        _DNS_TRANSACTION_STATE_MAX,
        _DNS_TRANSACTION_STATE_INVALID = -1
};

#include "resolved-dns-scope.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"

struct DnsTransaction {
        DnsScope *scope;

        DnsResourceKey *key;

        DnsTransactionState state;
        uint16_t id;

        bool initial_jitter;

        DnsPacket *sent, *received;
        DnsAnswer *cached;
        int cached_rcode;

        usec_t start_usec;
        sd_event_source *timeout_event_source;
        unsigned n_attempts;

        int dns_udp_fd;
        sd_event_source *dns_udp_event_source;

        /* The active server */
        DnsServer *server;

        /* TCP connection logic, if we need it */
        DnsStream *stream;

        /* Queries this transaction is referenced by and that shall be
         * notified about this specific transaction completing. */
        Set *queries;

        /* Zone items this transaction is referenced by and that shall
         * be notified about completion. */
        Set *zone_items;

        unsigned block_gc;

        LIST_FIELDS(DnsTransaction, transactions_by_scope);
};

int dns_transaction_new(DnsTransaction **ret, DnsScope *s, DnsResourceKey *key);
DnsTransaction* dns_transaction_free(DnsTransaction *t);

void dns_transaction_gc(DnsTransaction *t);
int dns_transaction_go(DnsTransaction *t);

void dns_transaction_process_reply(DnsTransaction *t, DnsPacket *p);
void dns_transaction_complete(DnsTransaction *t, DnsTransactionState state);

const char* dns_transaction_state_to_string(DnsTransactionState p) _const_;
DnsTransactionState dns_transaction_state_from_string(const char *s) _pure_;

/* LLMNR Jitter interval, see RFC 4795 Section 7 */
#define LLMNR_JITTER_INTERVAL_USEC (100 * USEC_PER_MSEC)

/* Maximum attempts to send DNS requests, across all DNS servers */
#define DNS_TRANSACTION_ATTEMPTS_MAX 16

/* Maximum attempts to send LLMNR requests, see RFC 4795 Section 2.7 */
#define LLMNR_TRANSACTION_ATTEMPTS_MAX 3

#define TRANSACTION_ATTEMPTS_MAX(p) (p == DNS_PROTOCOL_LLMNR ? LLMNR_TRANSACTION_ATTEMPTS_MAX : DNS_TRANSACTION_ATTEMPTS_MAX)
