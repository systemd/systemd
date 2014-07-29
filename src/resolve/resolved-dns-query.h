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

#include <inttypes.h>

#include "sd-bus.h"
#include "util.h"
#include "set.h"

typedef struct DnsQuery DnsQuery;
typedef struct DnsQueryTransaction DnsQueryTransaction;

#include "resolved.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-stream.h"

typedef enum DnsQueryState {
        DNS_QUERY_NULL,
        DNS_QUERY_PENDING,
        DNS_QUERY_FAILURE,
        DNS_QUERY_SUCCESS,
        DNS_QUERY_NO_SERVERS,
        DNS_QUERY_TIMEOUT,
        DNS_QUERY_ATTEMPTS_MAX,
        DNS_QUERY_INVALID_REPLY,
        DNS_QUERY_RESOURCES,
        DNS_QUERY_ABORTED,
} DnsQueryState;

struct DnsQueryTransaction {
        DnsScope *scope;

        DnsQuestion *question;

        DnsQueryState state;
        uint16_t id;

        DnsPacket *sent, *received;
        DnsAnswer *cached;
        int cached_rcode;

        sd_event_source *timeout_event_source;
        unsigned n_attempts;

        /* TCP connection logic, if we need it */
        DnsStream *stream;

        /* Queries this transaction is referenced by and that shall by
         * notified about this specific transaction completing. */
        Set *queries;

        unsigned block_gc;

        LIST_FIELDS(DnsQueryTransaction, transactions_by_scope);
};

struct DnsQuery {
        Manager *manager;
        DnsQuestion *question;

        DnsQueryState state;
        unsigned n_cname_redirects;

        sd_event_source *timeout_event_source;

        /* Discovered data */
        DnsAnswer *answer;
        int answer_ifindex;
        int answer_rcode;

        /* Bus client information */
        sd_bus_message *request;
        int request_family;
        const char *request_hostname;
        union in_addr_union request_address;

        /* Completion callback */
        void (*complete)(DnsQuery* q);
        unsigned block_ready;

        Set *transactions;

        LIST_FIELDS(DnsQuery, queries);
};

DnsQueryTransaction* dns_query_transaction_free(DnsQueryTransaction *t);
void dns_query_transaction_complete(DnsQueryTransaction *t, DnsQueryState state);

void dns_query_transaction_process_reply(DnsQueryTransaction *t, DnsPacket *p);

int dns_query_new(Manager *m, DnsQuery **q, DnsQuestion *question);
DnsQuery *dns_query_free(DnsQuery *q);

int dns_query_go(DnsQuery *q);
void dns_query_ready(DnsQuery *q);

int dns_query_cname_redirect(DnsQuery *q, const char *name);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);
