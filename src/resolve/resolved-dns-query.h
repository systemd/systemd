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


#include "sd-bus.h"
#include "set.h"

typedef struct DnsQuery DnsQuery;

#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-stream.h"

struct DnsQuery {
        Manager *manager;
        DnsQuestion *question;

        uint64_t flags;
        int ifindex;

        DnsTransactionState state;
        unsigned n_cname_redirects;

        sd_event_source *timeout_event_source;

        /* Discovered data */
        DnsAnswer *answer;
        int answer_family;
        DnsProtocol answer_protocol;
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

        sd_bus_track *bus_track;

        LIST_FIELDS(DnsQuery, queries);
};

int dns_query_new(Manager *m, DnsQuery **q, DnsQuestion *question, int family, uint64_t flags);
DnsQuery *dns_query_free(DnsQuery *q);

int dns_query_go(DnsQuery *q);
void dns_query_ready(DnsQuery *q);

int dns_query_cname_redirect(DnsQuery *q, const DnsResourceRecord *cname);

int dns_query_bus_track(DnsQuery *q, sd_bus_message *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuery*, dns_query_free);
