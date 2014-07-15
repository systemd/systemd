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

typedef struct DnsQuery DnsQuery;
typedef struct DnsQueryTransaction DnsQueryTransaction;

#include "resolved.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-packet.h"

typedef enum DnsQueryState {
        DNS_QUERY_NULL,
        DNS_QUERY_SENT,
        DNS_QUERY_FAILURE,
        DNS_QUERY_SUCCESS,
        DNS_QUERY_SKIPPED,
        DNS_QUERY_TIMEOUT,
        DNS_QUERY_ATTEMPTS_MAX,
        DNS_QUERY_INVALID_REPLY,
} DnsQueryState;

struct DnsQueryTransaction {
        DnsQuery *query;
        DnsScope *scope;

        DnsQueryState state;
        uint16_t id;

        sd_event_source *timeout_event_source;
        unsigned n_attempts;

        DnsPacket *packet;

        LIST_FIELDS(DnsQueryTransaction, transactions_by_query);
        LIST_FIELDS(DnsQueryTransaction, transactions_by_scope);
};

struct DnsQuery {
        Manager *manager;

        DnsResourceKey *keys;
        unsigned n_keys;

        DnsQueryState state;

        sd_event_source *timeout_event_source;

        uint16_t rcode;
        DnsPacket *packet;

        sd_bus_message *request;
        unsigned char request_family;
        const char *request_hostname;
        union in_addr_union request_address;

        void (*complete)(DnsQuery* q);

        LIST_HEAD(DnsQueryTransaction, transactions);
        LIST_FIELDS(DnsQuery, queries);
};

int dns_query_new(Manager *m, DnsQuery **q, DnsResourceKey *keys, unsigned n_keys);
DnsQuery *dns_query_free(DnsQuery *q);
int dns_query_start(DnsQuery *q);
void dns_query_finish(DnsQuery *q);

DnsQueryTransaction* dns_query_transaction_free(DnsQueryTransaction *t);
int dns_query_transaction_start(DnsQueryTransaction *t);
int dns_query_transaction_reply(DnsQueryTransaction *t, DnsPacket *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);
