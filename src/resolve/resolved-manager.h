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
#include "sd-netlink.h"
#include "sd-network.h"

#include "hashmap.h"
#include "list.h"
#include "ordered-set.h"
#include "resolve-util.h"

typedef struct Manager Manager;

#include "resolved-dns-query.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-trust-anchor.h"
#include "resolved-link.h"

#define MANAGER_SEARCH_DOMAINS_MAX 32
#define MANAGER_DNS_SERVERS_MAX 32

struct Manager {
        sd_event *event;

        ResolveSupport llmnr_support;
        ResolveSupport mdns_support;
        DnssecMode dnssec_mode;

        /* Network */
        Hashmap *links;

        sd_netlink *rtnl;
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
        LIST_HEAD(DnsServer, dns_servers);
        LIST_HEAD(DnsServer, fallback_dns_servers);
        unsigned n_dns_servers; /* counts both main and fallback */
        DnsServer *current_dns_server;

        LIST_HEAD(DnsSearchDomain, search_domains);
        unsigned n_search_domains;
        bool permit_domain_search;

        bool need_builtin_fallbacks:1;

        bool read_resolv_conf:1;
        usec_t resolv_conf_mtime;

        DnsTrustAnchor trust_anchor;

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

        /* mDNS */
        int mdns_ipv4_fd;
        int mdns_ipv6_fd;

        sd_event_source *mdns_ipv4_event_source;
        sd_event_source *mdns_ipv6_event_source;

        /* dbus */
        sd_bus *bus;
        sd_event_source *bus_retry_event_source;

        /* The hostname we publish on LLMNR and mDNS */
        char *llmnr_hostname;
        char *mdns_hostname;
        DnsResourceKey *llmnr_host_ipv4_key;
        DnsResourceKey *llmnr_host_ipv6_key;

        /* Watch the system hostname */
        int hostname_fd;
        sd_event_source *hostname_event_source;

        /* Watch for system suspends */
        sd_bus_slot *prepare_for_sleep_slot;

        sd_event_source *sigusr1_event_source;

        unsigned n_transactions_total;
        unsigned n_dnssec_verdict[_DNSSEC_VERDICT_MAX];

        /* Data from /etc/hosts */
        Set* etc_hosts_by_address;
        Hashmap* etc_hosts_by_name;
        usec_t etc_hosts_last, etc_hosts_mtime;
};

/* Manager */

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);

int manager_start(Manager *m);

uint32_t manager_find_mtu(Manager *m);

int manager_write(Manager *m, int fd, DnsPacket *p);
int manager_send(Manager *m, int fd, int ifindex, int family, const union in_addr_union *addr, uint16_t port, DnsPacket *p);
int manager_recv(Manager *m, int fd, DnsProtocol protocol, DnsPacket **ret);

int manager_find_ifindex(Manager *m, int family, const union in_addr_union *in_addr);
LinkAddress* manager_find_link_address(Manager *m, int family, const union in_addr_union *in_addr);

void manager_refresh_rrs(Manager *m);
int manager_next_hostname(Manager *m);

bool manager_our_packet(Manager *m, DnsPacket *p);
DnsScope* manager_find_scope(Manager *m, DnsPacket *p);

void manager_verify_all(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

#define EXTRA_CMSG_SPACE 1024

int manager_is_own_hostname(Manager *m, const char *name);

int manager_compile_dns_servers(Manager *m, OrderedSet **servers);
int manager_compile_search_domains(Manager *m, OrderedSet **domains);

DnssecMode manager_get_dnssec_mode(Manager *m);
bool manager_dnssec_supported(Manager *m);

void manager_dnssec_verdict(Manager *m, DnssecVerdict verdict, const DnsResourceKey *key);

bool manager_routable(Manager *m, int family);
