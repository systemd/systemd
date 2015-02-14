/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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
#include "list.h"
#include "hashmap.h"

typedef struct Manager Manager;
typedef enum Support Support;

enum Support {
        SUPPORT_NO,
        SUPPORT_YES,
        SUPPORT_RESOLVE,
        _SUPPORT_MAX,
        _SUPPORT_INVALID = -1
};

#include "resolved-dns-query.h"
#include "resolved-dns-stream.h"
#include "resolved-link.h"

struct Manager {
        sd_event *event;

        Support llmnr_support;

        /* Network */
        Hashmap *links;

        sd_rtnl *rtnl;
        sd_event_source *rtnl_event_source;

        sd_network_monitor *network_monitor;
        sd_event_source *network_event_source;

        /* DNS query management */
        Hashmap *dns_transactions;
        LIST_HEAD(DnsQuery, dns_queries);
        unsigned n_dns_queries;

        LIST_HEAD(DnsStream, dns_streams);
        unsigned n_dns_streams;

        /* Unicast dns */
        int dns_ipv4_fd;
        int dns_ipv6_fd;

        sd_event_source *dns_ipv4_event_source;
        sd_event_source *dns_ipv6_event_source;

        LIST_HEAD(DnsServer, dns_servers);
        LIST_HEAD(DnsServer, fallback_dns_servers);
        DnsServer *current_dns_server;

        bool read_resolv_conf;
        usec_t resolv_conf_mtime;

        LIST_HEAD(DnsScope, dns_scopes);
        DnsScope *unicast_scope;

        /* LLMNR */
        int llmnr_ipv4_udp_fd;
        int llmnr_ipv6_udp_fd;
        int llmnr_ipv4_tcp_fd;
        int llmnr_ipv6_tcp_fd;

        sd_event_source *llmnr_ipv4_udp_event_source;
        sd_event_source *llmnr_ipv6_udp_event_source;
        sd_event_source *llmnr_ipv4_tcp_event_source;
        sd_event_source *llmnr_ipv6_tcp_event_source;

        /* dbus */
        sd_bus *bus;
        sd_event_source *bus_retry_event_source;

        /* The hostname we publish on LLMNR and mDNS */
        char *hostname;
        DnsResourceKey *host_ipv4_key;
        DnsResourceKey *host_ipv6_key;

        /* Watch the system hostname */
        int hostname_fd;
        sd_event_source *hostname_event_source;

        /* Watch for system suspends */
        sd_bus_slot *prepare_for_sleep_slot;
};

/* Manager */

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_start(Manager *m);
int manager_read_resolv_conf(Manager *m);
int manager_write_resolv_conf(Manager *m);

DnsServer *manager_set_dns_server(Manager *m, DnsServer *s);
DnsServer *manager_find_dns_server(Manager *m, int family, const union in_addr_union *in_addr);
DnsServer *manager_get_dns_server(Manager *m);
void manager_next_dns_server(Manager *m);

uint32_t manager_find_mtu(Manager *m);

int manager_send(Manager *m, int fd, int ifindex, int family, const union in_addr_union *addr, uint16_t port, DnsPacket *p);
int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret);

int manager_dns_ipv4_fd(Manager *m);
int manager_dns_ipv6_fd(Manager *m);
int manager_llmnr_ipv4_udp_fd(Manager *m);
int manager_llmnr_ipv6_udp_fd(Manager *m);
int manager_llmnr_ipv4_tcp_fd(Manager *m);
int manager_llmnr_ipv6_tcp_fd(Manager *m);

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr);
LinkAddress* manager_find_link_address(Manager *m, int family, const union in_addr_union *in_addr);

void manager_refresh_rrs(Manager *m);
int manager_next_hostname(Manager *m);

bool manager_our_packet(Manager *m, DnsPacket *p);
DnsScope* manager_find_scope(Manager *m, DnsPacket *p);

void manager_verify_all(Manager *m);

void manager_flush_dns_servers(Manager *m, DnsServerType t);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

#define EXTRA_CMSG_SPACE 1024

const char* support_to_string(Support p) _const_;
int support_from_string(const char *s) _pure_;
