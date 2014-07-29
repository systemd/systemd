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

#include "list.h"

typedef struct DnsScope DnsScope;

#include "resolved.h"
#include "resolved-link.h"
#include "resolved-dns-server.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-query.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-zone.h"
#include "resolved-dns-stream.h"

typedef enum DnsScopeMatch {
        DNS_SCOPE_NO,
        DNS_SCOPE_MAYBE,
        DNS_SCOPE_YES,
        _DNS_SCOPE_MATCH_MAX,
        _DNS_SCOPE_INVALID = -1
} DnsScopeMatch;

struct DnsScope {
        Manager *manager;

        DnsProtocol protocol;
        int family;

        Link *link;

        char **domains;

        DnsCache cache;
        DnsZone zone;

        LIST_HEAD(DnsQueryTransaction, transactions);

        LIST_FIELDS(DnsScope, scopes);
};

int dns_scope_new(Manager *m, DnsScope **ret, Link *l, DnsProtocol p, int family);
DnsScope* dns_scope_free(DnsScope *s);

int dns_scope_send(DnsScope *s, DnsPacket *p);
int dns_scope_tcp_socket(DnsScope *s, int family, const union in_addr_union *address, uint16_t port);

DnsScopeMatch dns_scope_good_domain(DnsScope *s, const char *domain);
int dns_scope_good_key(DnsScope *s, DnsResourceKey *key);
int dns_scope_good_dns_server(DnsScope *s, int family, const union in_addr_union *address);

DnsServer *dns_scope_get_server(DnsScope *s);
void dns_scope_next_dns_server(DnsScope *s);

int dns_scope_llmnr_membership(DnsScope *s, bool b);

void dns_scope_process_query(DnsScope *s, DnsStream *stream, DnsPacket *p);
