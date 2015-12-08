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

#include "alloc-util.h"
#include "missing.h"
#include "parse-util.h"
#include "resolved-link.h"
#include "string-util.h"
#include "strv.h"

int link_new(Manager *m, Link **ret, int ifindex) {
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);

        r = hashmap_ensure_allocated(&m->links, NULL);
        if (r < 0)
                return r;

        l = new0(Link, 1);
        if (!l)
                return -ENOMEM;

        l->ifindex = ifindex;
        l->llmnr_support = SUPPORT_YES;

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

        dns_server_unlink_marked(l->dns_servers);
        dns_search_domain_unlink_all(l->search_domains);

        while (l->addresses)
                link_address_free(l->addresses);

        if (l->manager)
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));

        dns_scope_free(l->unicast_scope);
        dns_scope_free(l->llmnr_ipv4_scope);
        dns_scope_free(l->llmnr_ipv6_scope);

        free(l);
        return NULL;
}

static void link_allocate_scopes(Link *l) {
        int r;

        assert(l);

        if (l->dns_servers) {
                if (!l->unicast_scope) {
                        r = dns_scope_new(l->manager, &l->unicast_scope, l, DNS_PROTOCOL_DNS, AF_UNSPEC);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate DNS scope: %m");
                }
        } else
                l->unicast_scope = dns_scope_free(l->unicast_scope);

        if (link_relevant(l, AF_INET) &&
            l->llmnr_support != SUPPORT_NO &&
            l->manager->llmnr_support != SUPPORT_NO) {
                if (!l->llmnr_ipv4_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv4_scope, l, DNS_PROTOCOL_LLMNR, AF_INET);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate LLMNR IPv4 scope: %m");
                }
        } else
                l->llmnr_ipv4_scope = dns_scope_free(l->llmnr_ipv4_scope);

        if (link_relevant(l, AF_INET6) &&
            l->llmnr_support != SUPPORT_NO &&
            l->manager->llmnr_support != SUPPORT_NO &&
            socket_ipv6_is_supported()) {
                if (!l->llmnr_ipv6_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv6_scope, l, DNS_PROTOCOL_LLMNR, AF_INET6);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate LLMNR IPv6 scope: %m");
                }
        } else
                l->llmnr_ipv6_scope = dns_scope_free(l->llmnr_ipv6_scope);
}

void link_add_rrs(Link *l, bool force_remove) {
        LinkAddress *a;

        LIST_FOREACH(addresses, a, l->addresses)
                link_address_add_rrs(a, force_remove);
}

int link_update_rtnl(Link *l, sd_netlink_message *m) {
        const char *n = NULL;
        int r;

        assert(l);
        assert(m);

        r = sd_rtnl_message_link_get_flags(m, &l->flags);
        if (r < 0)
                return r;

        sd_netlink_message_read_u32(m, IFLA_MTU, &l->mtu);

        if (sd_netlink_message_read_string(m, IFLA_IFNAME, &n) >= 0) {
                strncpy(l->name, n, sizeof(l->name)-1);
                char_array_0(l->name);
        }

        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return 0;
}

static int link_update_dns_servers(Link *l) {
        _cleanup_strv_free_ char **nameservers = NULL;
        char **nameserver;
        int r;

        assert(l);

        r = sd_network_link_get_dns(l->ifindex, &nameservers);
        if (r < 0)
                goto clear;

        dns_server_mark_all(l->dns_servers);

        STRV_FOREACH(nameserver, nameservers) {
                union in_addr_union a;
                DnsServer *s;
                int family;

                r = in_addr_from_string_auto(*nameserver, &family, &a);
                if (r < 0)
                        goto clear;

                s = dns_server_find(l->dns_servers, family, &a);
                if (s)
                        dns_server_move_back_and_unmark(s);
                else {
                        r = dns_server_new(l->manager, NULL, DNS_SERVER_LINK, l, family, &a);
                        if (r < 0)
                                goto clear;
                }
        }

        dns_server_unlink_marked(l->dns_servers);
        return 0;

clear:
        dns_server_unlink_all(l->dns_servers);
        return r;
}

static int link_update_llmnr_support(Link *l) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(l);

        r = sd_network_link_get_llmnr(l->ifindex, &b);
        if (r < 0)
                goto clear;

        r = parse_boolean(b);
        if (r < 0) {
                if (streq(b, "resolve"))
                        l->llmnr_support = SUPPORT_RESOLVE;
                else
                        goto clear;

        } else if (r > 0)
                l->llmnr_support = SUPPORT_YES;
        else
                l->llmnr_support = SUPPORT_NO;

        return 0;

clear:
        l->llmnr_support = SUPPORT_YES;
        return r;
}

static int link_update_search_domains(Link *l) {
        _cleanup_strv_free_ char **domains = NULL;
        char **i;
        int r;

        assert(l);

        r = sd_network_link_get_domains(l->ifindex, &domains);
        if (r < 0)
                goto clear;

        dns_search_domain_mark_all(l->search_domains);

        STRV_FOREACH(i, domains) {
                DnsSearchDomain *d;

                r = dns_search_domain_find(l->search_domains, *i, &d);
                if (r < 0)
                        goto clear;

                if (r > 0)
                        dns_search_domain_move_back_and_unmark(d);
                else {
                        r = dns_search_domain_new(l->manager, NULL, DNS_SEARCH_DOMAIN_LINK, l, *i);
                        if (r < 0)
                                goto clear;
                }
        }

        dns_search_domain_unlink_marked(l->search_domains);
        return 0;

clear:
        dns_search_domain_unlink_all(l->search_domains);
        return r;
}

int link_update_monitor(Link *l) {
        int r;

        assert(l);

        link_update_dns_servers(l);
        link_update_llmnr_support(l);
        link_allocate_scopes(l);

        r = link_update_search_domains(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read search domains for interface %s, ignoring: %m", l->name);

        link_add_rrs(l, false);

        return 0;
}

bool link_relevant(Link *l, int family) {
        _cleanup_free_ char *state = NULL;
        LinkAddress *a;

        assert(l);

        /* A link is relevant if it isn't a loopback or pointopoint
         * device, has a link beat, can do multicast and has at least
         * one relevant IP address */

        if (l->flags & (IFF_LOOPBACK|IFF_POINTOPOINT|IFF_DORMANT))
                return false;

        if ((l->flags & (IFF_UP|IFF_LOWER_UP|IFF_MULTICAST)) != (IFF_UP|IFF_LOWER_UP|IFF_MULTICAST))
                return false;

        sd_network_link_get_operational_state(l->ifindex, &state);
        if (state && !STR_IN_SET(state, "unknown", "degraded", "routable"))
                return false;

        LIST_FOREACH(addresses, a, l->addresses)
                if (a->family == family && link_address_relevant(a))
                        return true;

        return false;
}

LinkAddress *link_find_address(Link *l, int family, const union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(l);

        LIST_FOREACH(addresses, a, l->addresses)
                if (a->family == family && in_addr_equal(family, &a->in_addr, in_addr))
                        return a;

        return NULL;
}

DnsServer* link_set_dns_server(Link *l, DnsServer *s) {
        assert(l);

        if (l->current_dns_server == s)
                return s;

        if (s) {
                _cleanup_free_ char *ip = NULL;

                in_addr_to_string(s->family, &s->address, &ip);
                log_info("Switching to DNS server %s for interface %s.", strna(ip), l->name);
        }

        dns_server_unref(l->current_dns_server);
        l->current_dns_server = dns_server_ref(s);

        if (l->unicast_scope)
                dns_cache_flush(&l->unicast_scope->cache);

        return s;
}

DnsServer *link_get_dns_server(Link *l) {
        assert(l);

        if (!l->current_dns_server)
                link_set_dns_server(l, l->dns_servers);

        return l->current_dns_server;
}

void link_next_dns_server(Link *l) {
        assert(l);

        if (!l->current_dns_server)
                return;

        /* Change to the next one, but make sure to follow the linked
         * list only if this server is actually still linked. */
        if (l->current_dns_server->linked && l->current_dns_server->servers_next) {
                link_set_dns_server(l, l->current_dns_server->servers_next);
                return;
        }

        link_set_dns_server(l, l->dns_servers);
}

int link_address_new(Link *l, LinkAddress **ret, int family, const union in_addr_union *in_addr) {
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

        if (a->link) {
                LIST_REMOVE(addresses, a->link->addresses, a);

                if (a->llmnr_address_rr) {
                        if (a->family == AF_INET && a->link->llmnr_ipv4_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_address_rr);
                        else if (a->family == AF_INET6 && a->link->llmnr_ipv6_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_address_rr);
                }

                if (a->llmnr_ptr_rr) {
                        if (a->family == AF_INET && a->link->llmnr_ipv4_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_ptr_rr);
                        else if (a->family == AF_INET6 && a->link->llmnr_ipv6_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_ptr_rr);
                }
        }

        dns_resource_record_unref(a->llmnr_address_rr);
        dns_resource_record_unref(a->llmnr_ptr_rr);

        free(a);
        return NULL;
}

void link_address_add_rrs(LinkAddress *a, bool force_remove) {
        int r;

        assert(a);

        if (a->family == AF_INET) {

                if (!force_remove &&
                    link_address_relevant(a) &&
                    a->link->llmnr_ipv4_scope &&
                    a->link->llmnr_support == SUPPORT_YES &&
                    a->link->manager->llmnr_support == SUPPORT_YES) {

                        if (!a->link->manager->llmnr_host_ipv4_key) {
                                a->link->manager->llmnr_host_ipv4_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, a->link->manager->llmnr_hostname);
                                if (!a->link->manager->llmnr_host_ipv4_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->llmnr_address_rr) {
                                a->llmnr_address_rr = dns_resource_record_new(a->link->manager->llmnr_host_ipv4_key);
                                if (!a->llmnr_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->llmnr_address_rr->a.in_addr = a->in_addr.in;
                                a->llmnr_address_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        if (!a->llmnr_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->llmnr_ptr_rr, a->family, &a->in_addr, a->link->manager->llmnr_hostname);
                                if (r < 0)
                                        goto fail;

                                a->llmnr_ptr_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_address_rr, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add A record to LLMNR zone: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_ptr_rr, false);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add IPv6 PTR record to LLMNR zone: %m");
                } else {
                        if (a->llmnr_address_rr) {
                                if (a->link->llmnr_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_address_rr);
                                a->llmnr_address_rr = dns_resource_record_unref(a->llmnr_address_rr);
                        }

                        if (a->llmnr_ptr_rr) {
                                if (a->link->llmnr_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_ptr_rr);
                                a->llmnr_ptr_rr = dns_resource_record_unref(a->llmnr_ptr_rr);
                        }
                }
        }

        if (a->family == AF_INET6) {

                if (!force_remove &&
                    link_address_relevant(a) &&
                    a->link->llmnr_ipv6_scope &&
                    a->link->llmnr_support == SUPPORT_YES &&
                    a->link->manager->llmnr_support == SUPPORT_YES) {

                        if (!a->link->manager->llmnr_host_ipv6_key) {
                                a->link->manager->llmnr_host_ipv6_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, a->link->manager->llmnr_hostname);
                                if (!a->link->manager->llmnr_host_ipv6_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->llmnr_address_rr) {
                                a->llmnr_address_rr = dns_resource_record_new(a->link->manager->llmnr_host_ipv6_key);
                                if (!a->llmnr_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->llmnr_address_rr->aaaa.in6_addr = a->in_addr.in6;
                                a->llmnr_address_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        if (!a->llmnr_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->llmnr_ptr_rr, a->family, &a->in_addr, a->link->manager->llmnr_hostname);
                                if (r < 0)
                                        goto fail;

                                a->llmnr_ptr_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_address_rr, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add AAAA record to LLMNR zone: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_ptr_rr, false);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add IPv6 PTR record to LLMNR zone: %m");
                } else {
                        if (a->llmnr_address_rr) {
                                if (a->link->llmnr_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_address_rr);
                                a->llmnr_address_rr = dns_resource_record_unref(a->llmnr_address_rr);
                        }

                        if (a->llmnr_ptr_rr) {
                                if (a->link->llmnr_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_ptr_rr);
                                a->llmnr_ptr_rr = dns_resource_record_unref(a->llmnr_ptr_rr);
                        }
                }
        }

        return;

fail:
        log_debug_errno(r, "Failed to update address RRs: %m");
}

int link_address_update_rtnl(LinkAddress *a, sd_netlink_message *m) {
        int r;
        assert(a);
        assert(m);

        r = sd_rtnl_message_addr_get_flags(m, &a->flags);
        if (r < 0)
                return r;

        sd_rtnl_message_addr_get_scope(m, &a->scope);

        link_allocate_scopes(a->link);
        link_add_rrs(a->link, false);

        return 0;
}

bool link_address_relevant(LinkAddress *a) {
        assert(a);

        if (a->flags & (IFA_F_DEPRECATED|IFA_F_TENTATIVE))
                return false;

        if (IN_SET(a->scope, RT_SCOPE_HOST, RT_SCOPE_NOWHERE))
                return false;

        return true;
}
