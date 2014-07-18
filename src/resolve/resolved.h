/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "sd-event.h"
#include "sd-network.h"
#include "sd-rtnl.h"
#include "util.h"
#include "list.h"
#include "in-addr-util.h"
#include "hashmap.h"

typedef struct Manager Manager;

#include "resolved-dns-query.h"
#include "resolved-dns-server.h"
#include "resolved-dns-scope.h"

struct Manager {
        sd_event *event;

        bool use_llmnr:1;

        /* Network */
        Hashmap *links;

        sd_rtnl *rtnl;
        sd_event_source *rtnl_event_source;

        sd_network_monitor *network_monitor;
        sd_event_source *network_event_source;

        /* DNS query management */
        Hashmap *dns_query_transactions;
        LIST_HEAD(DnsQuery, dns_queries);
        unsigned n_dns_queries;

        /* Unicast dns */
        int dns_ipv4_fd;
        int dns_ipv6_fd;

        sd_event_source *dns_ipv4_event_source;
        sd_event_source *dns_ipv6_event_source;

        LIST_HEAD(DnsServer, dns_servers);
        DnsServer *current_dns_server;

        LIST_HEAD(DnsScope, dns_scopes);
        DnsScope *unicast_scope;

        /* LLMNR */
        int llmnr_ipv4_udp_fd;
        int llmnr_ipv6_udp_fd;
        /* int llmnr_ipv4_tcp_fd; */
        /* int llmnr_ipv6_tcp_fd; */

        sd_event_source *llmnr_ipv4_udp_event_source;
        sd_event_source *llmnr_ipv6_udp_event_source;

        /* dbus */
        sd_bus *bus;
        sd_event_source *bus_retry_event_source;
};

/* Manager */

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_parse_config_file(Manager *m);
int manager_write_resolv_conf(Manager *m);

DnsServer* manager_find_dns_server(Manager *m, int family, union in_addr_union *in_addr);
DnsServer *manager_get_dns_server(Manager *m);
void manager_next_dns_server(Manager *m);
uint32_t manager_find_mtu(Manager *m);

int manager_send(Manager *m, int fd, int ifindex, int family, union in_addr_union *addr, uint16_t port, DnsPacket *p);
int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret);

int manager_dns_ipv4_fd(Manager *m);
int manager_dns_ipv6_fd(Manager *m);
int manager_llmnr_ipv4_udp_fd(Manager *m);
int manager_llmnr_ipv6_udp_fd(Manager *m);

int manager_connect_bus(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

const struct ConfigPerfItem* resolved_gperf_lookup(const char *key, unsigned length);
int config_parse_dnsv(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
