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
        DNS_QUERY_PENDING,
        DNS_QUERY_FAILURE,
        DNS_QUERY_SUCCESS,
        DNS_QUERY_NO_SERVERS,
        DNS_QUERY_TIMEOUT,
        DNS_QUERY_ATTEMPTS_MAX,
        DNS_QUERY_INVALID_REPLY,
        DNS_QUERY_RESOURCES
} DnsQueryState;

struct DnsQueryTransaction {
        DnsQuery *query;
        DnsScope *scope;

        DnsQueryState state;
        uint16_t id;

        sd_event_source *timeout_event_source;
        unsigned n_attempts;

        DnsPacket *sent, *received;

        /* TCP connection logic */
        int tcp_fd;
        sd_event_source *tcp_event_source;
        size_t tcp_written, tcp_read;
        be16_t tcp_read_size;

        /* Data from cache */
        DnsResourceRecord **cached_rrs;
        unsigned n_cached_rrs;

        LIST_FIELDS(DnsQueryTransaction, transactions_by_query);
        LIST_FIELDS(DnsQueryTransaction, transactions_by_scope);
};

struct DnsQuery {
        Manager *manager;

        DnsResourceKey *keys;
        unsigned n_keys;

        DnsQueryState state;
        unsigned n_cname;

        sd_event_source *timeout_event_source;

        /* Discovered data */
        DnsPacket *received;
        DnsResourceRecord **cached_rrs;
        unsigned n_cached_rrs;

        /* Bus client information */
        sd_bus_message *request;
        int request_family;
        const char *request_hostname;
        union in_addr_union request_address;

        /* Completion callback */
        void (*complete)(DnsQuery* q);
        unsigned block_finish;

        LIST_HEAD(DnsQueryTransaction, transactions);
        LIST_FIELDS(DnsQuery, queries);
};

DnsQueryTransaction* dns_query_transaction_free(DnsQueryTransaction *t);
void dns_query_transaction_reply(DnsQueryTransaction *t, DnsPacket *p);

int dns_query_new(Manager *m, DnsQuery **q, DnsResourceKey *keys, unsigned n_keys);
DnsQuery *dns_query_free(DnsQuery *q);

int dns_query_go(DnsQuery *q);
int dns_query_cname_redirect(DnsQuery *q, const char *name);
void dns_query_finish(DnsQuery *q);

int dns_query_matches_rr(DnsQuery *q, DnsResourceRecord *rr);
int dns_query_matches_cname(DnsQuery *q, DnsResourceRecord *rr);

/* What we found */
int dns_query_get_rrs(DnsQuery *q, DnsResourceRecord *** rrs);
int dns_query_get_rcode(DnsQuery *q);
int dns_query_get_ifindex(DnsQuery *q);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);
