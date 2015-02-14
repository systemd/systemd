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

#include <net/if.h>

#include "in-addr-util.h"
#include "ratelimit.h"

typedef struct Link Link;
typedef struct LinkAddress LinkAddress;

#include "resolved-dns-rr.h"
#include "resolved-manager.h"

struct LinkAddress {
        Link *link;

        int family;
        union in_addr_union in_addr;

        unsigned char flags, scope;

        DnsResourceRecord *llmnr_address_rr;
        DnsResourceRecord *llmnr_ptr_rr;

        LIST_FIELDS(LinkAddress, addresses);
};

struct Link {
        Manager *manager;

        int ifindex;
        unsigned flags;

        LIST_HEAD(LinkAddress, addresses);

        LIST_HEAD(DnsServer, dns_servers);
        DnsServer *current_dns_server;

        Support llmnr_support;

        DnsScope *unicast_scope;
        DnsScope *llmnr_ipv4_scope;
        DnsScope *llmnr_ipv6_scope;

        char name[IF_NAMESIZE];
        uint32_t mtu;
};

int link_new(Manager *m, Link **ret, int ifindex);
Link *link_free(Link *l);
int link_update_rtnl(Link *l, sd_rtnl_message *m);
int link_update_monitor(Link *l);
bool link_relevant(Link *l, int family);
LinkAddress* link_find_address(Link *l, int family, const union in_addr_union *in_addr);
void link_add_rrs(Link *l, bool force_remove);

DnsServer* link_set_dns_server(Link *l, DnsServer *s);
DnsServer* link_find_dns_server(Link *l, int family, const union in_addr_union *in_addr);
DnsServer* link_get_dns_server(Link *l);
void link_next_dns_server(Link *l);

int link_address_new(Link *l, LinkAddress **ret, int family, const union in_addr_union *in_addr);
LinkAddress *link_address_free(LinkAddress *a);
int link_address_update_rtnl(LinkAddress *a, sd_rtnl_message *m);
bool link_address_relevant(LinkAddress *l);
void link_address_add_rrs(LinkAddress *a, bool force_remove);

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
