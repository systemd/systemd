/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "sd-network.h"
#include "dhcp-lease-internal.h"
#include "strv.h"
#include "resolved-link.h"

int link_new(Manager *m, Link **ret, int ifindex) {
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);

        r = hashmap_ensure_allocated(&m->links, NULL, NULL);
        if (r < 0)
                return r;

        l = new0(Link, 1);
        if (!l)
                return -ENOMEM;

        l->ifindex = ifindex;

        r = hashmap_put(m->links, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        l->manager = m;

        if (ret)
                *ret = l;
        l = NULL;

        return 0;
}

Link *link_free(Link *l) {

        if (!l)
                return NULL;

        while (l->addresses)
                link_address_free(l->addresses);

        if (l->manager)
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));

        dns_scope_free(l->unicast_scope);
        dns_scope_free(l->mdns_ipv4_scope);
        dns_scope_free(l->mdns_ipv6_scope);

        while (l->dhcp_dns_servers)
                dns_server_free(l->dhcp_dns_servers);

        while (l->link_dns_servers)
                dns_server_free(l->link_dns_servers);

        free(l);
        return NULL;
 }

int link_update_rtnl(Link *l, sd_rtnl_message *m) {
        int r;

        assert(l);
        assert(m);

        r = sd_rtnl_message_link_get_flags(m, &l->flags);
        if (r < 0)
                return r;

        return 0;
}

static int update_dhcp_dns_servers(Link *l) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        struct in_addr *nameservers = NULL;
        DnsServer *s, *nx;
        unsigned i;
        size_t n;
        int r;

        assert(l);

        r = sd_network_dhcp_use_dns(l->ifindex);
        if (r <= 0)
                goto clear;

        r = sd_network_get_dhcp_lease(l->ifindex, &lease);
        if (r < 0)
                goto clear;

        LIST_FOREACH(servers, s, l->dhcp_dns_servers)
                s->marked = true;

        r = sd_dhcp_lease_get_dns(lease, &nameservers, &n);
        if (r < 0)
                goto clear;

        for (i = 0; i < n; i++) {
                union in_addr_union a = { .in = nameservers[i] };

                s = link_find_dns_server(l, DNS_SERVER_DHCP, AF_INET, &a);
                if (s)
                        s->marked = false;
                else {
                        r = dns_server_new(l->manager, NULL, DNS_SERVER_DHCP, l, AF_INET, &a);
                        if (r < 0)
                                goto clear;
                }
        }

        LIST_FOREACH_SAFE(servers, s, nx, l->dhcp_dns_servers)
                if (s->marked)
                        dns_server_free(s);

        return 0;

clear:
        while (l->dhcp_dns_servers)
                dns_server_free(l->dhcp_dns_servers);

        return r;
}

static int update_link_dns_servers(Link *l) {
        _cleanup_free_ struct in_addr *nameservers = NULL;
        _cleanup_free_ struct in6_addr *nameservers6 = NULL;
        DnsServer *s, *nx;
        unsigned i;
        size_t n;
        int r;

        assert(l);

        LIST_FOREACH(servers, s, l->link_dns_servers)
                s->marked = true;

        r = sd_network_get_dns(l->ifindex, &nameservers, &n);
        if (r < 0)
                goto clear;

        for (i = 0; i < n; i++) {
                union in_addr_union a = { .in = nameservers[i] };

                s = link_find_dns_server(l, DNS_SERVER_LINK, AF_INET, &a);
                if (s)
                        s->marked = false;
                else {
                        r = dns_server_new(l->manager, NULL, DNS_SERVER_LINK, l, AF_INET, &a);
                        if (r < 0)
                                goto clear;
                }
        }

        r = sd_network_get_dns6(l->ifindex, &nameservers6, &n);
        if (r < 0)
                goto clear;

        for (i = 0; i < n; i++) {
                union in_addr_union a = { .in6 = nameservers6[i] };

                s = link_find_dns_server(l, DNS_SERVER_LINK, AF_INET6, &a);
                if (s)
                        s->marked = false;
                else {
                        r = dns_server_new(l->manager, NULL, DNS_SERVER_LINK, l, AF_INET6, &a);
                        if (r < 0)
                                goto clear;
                }
        }

        LIST_FOREACH_SAFE(servers, s, nx, l->link_dns_servers)
                if (s->marked)
                        dns_server_free(s);

        return 0;

clear:
        while (l->link_dns_servers)
                dns_server_free(l->link_dns_servers);

        return r;
}

int link_update_monitor(Link *l) {
        assert(l);

        free(l->operational_state);
        l->operational_state = NULL;

        sd_network_get_link_operational_state(l->ifindex, &l->operational_state);

        update_dhcp_dns_servers(l);
        update_link_dns_servers(l);

        return 0;
}

bool link_relevant(Link *l) {
        LinkAddress *a;

        assert(l);

        /* A link is relevant if it isn't a loopback device and has at
         * least one relevant IP address */

        if (l->flags & IFF_LOOPBACK)
                return false;

        if (l->operational_state && !STR_IN_SET(l->operational_state, "unknown", "degraded", "routable"))
                return false;

        LIST_FOREACH(addresses, a, l->addresses)
                if (link_address_relevant(a))
                        return true;

        return false;
}

LinkAddress *link_find_address(Link *l, unsigned char family, union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(l);

        LIST_FOREACH(addresses, a, l->addresses) {

                if (a->family == family &&
                    in_addr_equal(family, &a->in_addr, in_addr))
                        return a;
        }

        return NULL;
}

DnsServer* link_find_dns_server(Link *l, DnsServerSource source, unsigned char family, union in_addr_union *in_addr) {
        DnsServer *first, *s;

        assert(l);

        first = source == DNS_SERVER_DHCP ? l->dhcp_dns_servers : l->link_dns_servers;

        LIST_FOREACH(servers, s, first) {

                if (s->family == family &&
                    in_addr_equal(family, &s->address, in_addr))
                        return s;
        }

        return NULL;
}

DnsServer *link_get_dns_server(Link *l) {
        assert(l);

        if (!l->current_dns_server)
                l->current_dns_server = l->link_dns_servers;
        if (!l->current_dns_server)
                l->current_dns_server = l->dhcp_dns_servers;

        return l->current_dns_server;
}

void link_next_dns_server(Link *l) {
        assert(l);

        /* Switch to the next DNS server */

        if (!l->current_dns_server) {
                l->current_dns_server = l->link_dns_servers;
                if (l->current_dns_server)
                        return;
        }

        if (!l->current_dns_server) {
                l->current_dns_server = l->dhcp_dns_servers;
                if (l->current_dns_server)
                        return;
        }

        if (!l->current_dns_server)
                return;

        if (l->current_dns_server->servers_next) {
                l->current_dns_server = l->current_dns_server->servers_next;
                return;
        }

        if (l->current_dns_server->source == DNS_SERVER_LINK)
                l->current_dns_server = l->dhcp_dns_servers;
        else {
                assert(l->current_dns_server->source == DNS_SERVER_DHCP);
                l->current_dns_server = l->link_dns_servers;
        }
}

int link_address_new(Link *l, LinkAddress **ret, unsigned char family, union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(l);
        assert(in_addr);

        a = new0(LinkAddress, 1);
        if (!a)
                return -ENOMEM;

        a->family = family;
        a->in_addr = *in_addr;

        a->link = l;
        LIST_PREPEND(addresses, l->addresses, a);

        if (ret)
                *ret = a;

        return 0;
}

LinkAddress *link_address_free(LinkAddress *a) {
        if (!a)
                return NULL;

        if (a->link)
                LIST_REMOVE(addresses, a->link->addresses, a);

        free(a);
        return NULL;
}

int link_address_update_rtnl(LinkAddress *a, sd_rtnl_message *m) {
        int r;
        assert(a);
        assert(m);

        r = sd_rtnl_message_addr_get_flags(m, &a->flags);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_get_scope(m, &a->scope);
        if (r < 0)
                return r;

        return 0;
}

bool link_address_relevant(LinkAddress *a) {
        assert(a);

        if (a->flags & IFA_F_DEPRECATED)
                return false;

        if (IN_SET(a->scope, RT_SCOPE_HOST, RT_SCOPE_NOWHERE))
                return false;

        return true;
}
