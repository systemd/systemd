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
        l->llmnr_support = RESOLVE_SUPPORT_YES;
        l->mdns_support = RESOLVE_SUPPORT_NO;
        l->dnssec_mode = _DNSSEC_MODE_INVALID;
        l->operstate = IF_OPER_UNKNOWN;

        r = hashmap_put(m->links, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        l->manager = m;

        if (ret)
                *ret = l;
        l = NULL;

        return 0;
}

void link_flush_settings(Link *l) {
        assert(l);

        l->llmnr_support = RESOLVE_SUPPORT_YES;
        l->mdns_support = RESOLVE_SUPPORT_NO;
        l->dnssec_mode = _DNSSEC_MODE_INVALID;

        dns_server_unlink_all(l->dns_servers);
        dns_search_domain_unlink_all(l->search_domains);

        l->dnssec_negative_trust_anchors = set_free_free(l->dnssec_negative_trust_anchors);
}

Link *link_free(Link *l) {
        if (!l)
                return NULL;

        link_flush_settings(l);

        while (l->addresses)
                (void) link_address_free(l->addresses);

        if (l->manager)
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));

        dns_scope_free(l->unicast_scope);
        dns_scope_free(l->llmnr_ipv4_scope);
        dns_scope_free(l->llmnr_ipv6_scope);
        dns_scope_free(l->mdns_ipv4_scope);
        dns_scope_free(l->mdns_ipv6_scope);

        free(l);
        return NULL;
}

void link_allocate_scopes(Link *l) {
        int r;

        assert(l);

        if (link_relevant(l, AF_UNSPEC, false) &&
            l->dns_servers) {
                if (!l->unicast_scope) {
                        r = dns_scope_new(l->manager, &l->unicast_scope, l, DNS_PROTOCOL_DNS, AF_UNSPEC);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate DNS scope: %m");
                }
        } else
                l->unicast_scope = dns_scope_free(l->unicast_scope);

        if (link_relevant(l, AF_INET, true) &&
            l->llmnr_support != RESOLVE_SUPPORT_NO &&
            l->manager->llmnr_support != RESOLVE_SUPPORT_NO) {
                if (!l->llmnr_ipv4_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv4_scope, l, DNS_PROTOCOL_LLMNR, AF_INET);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate LLMNR IPv4 scope: %m");
                }
        } else
                l->llmnr_ipv4_scope = dns_scope_free(l->llmnr_ipv4_scope);

        if (link_relevant(l, AF_INET6, true) &&
            l->llmnr_support != RESOLVE_SUPPORT_NO &&
            l->manager->llmnr_support != RESOLVE_SUPPORT_NO &&
            socket_ipv6_is_supported()) {
                if (!l->llmnr_ipv6_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv6_scope, l, DNS_PROTOCOL_LLMNR, AF_INET6);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate LLMNR IPv6 scope: %m");
                }
        } else
                l->llmnr_ipv6_scope = dns_scope_free(l->llmnr_ipv6_scope);

        if (link_relevant(l, AF_INET, true) &&
            l->mdns_support != RESOLVE_SUPPORT_NO &&
            l->manager->mdns_support != RESOLVE_SUPPORT_NO) {
                if (!l->mdns_ipv4_scope) {
                        r = dns_scope_new(l->manager, &l->mdns_ipv4_scope, l, DNS_PROTOCOL_MDNS, AF_INET);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate mDNS IPv4 scope: %m");
                }
        } else
                l->mdns_ipv4_scope = dns_scope_free(l->mdns_ipv4_scope);

        if (link_relevant(l, AF_INET6, true) &&
            l->mdns_support != RESOLVE_SUPPORT_NO &&
            l->manager->mdns_support != RESOLVE_SUPPORT_NO) {
                if (!l->mdns_ipv6_scope) {
                        r = dns_scope_new(l->manager, &l->mdns_ipv6_scope, l, DNS_PROTOCOL_MDNS, AF_INET6);
                        if (r < 0)
                                log_warning_errno(r, "Failed to allocate mDNS IPv6 scope: %m");
                }
        } else
                l->mdns_ipv6_scope = dns_scope_free(l->mdns_ipv6_scope);
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

        (void) sd_netlink_message_read_u32(m, IFLA_MTU, &l->mtu);
        (void) sd_netlink_message_read_u8(m, IFLA_OPERSTATE, &l->operstate);

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
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
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
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        l->llmnr_support = resolve_support_from_string(b);
        if (l->llmnr_support < 0) {
                r = -EINVAL;
                goto clear;
        }

        return 0;

clear:
        l->llmnr_support = RESOLVE_SUPPORT_YES;
        return r;
}

static int link_update_mdns_support(Link *l) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(l);

        r = sd_network_link_get_mdns(l->ifindex, &b);
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        l->mdns_support = resolve_support_from_string(b);
        if (l->mdns_support < 0) {
                r = -EINVAL;
                goto clear;
        }

        return 0;

clear:
        l->mdns_support = RESOLVE_SUPPORT_NO;
        return r;
}

void link_set_dnssec_mode(Link *l, DnssecMode mode) {

        assert(l);

        if (l->dnssec_mode == mode)
                return;

        if ((l->dnssec_mode == _DNSSEC_MODE_INVALID) ||
            (l->dnssec_mode == DNSSEC_NO && mode != DNSSEC_NO) ||
            (l->dnssec_mode == DNSSEC_ALLOW_DOWNGRADE && mode == DNSSEC_YES)) {

                /* When switching from non-DNSSEC mode to DNSSEC mode, flush the cache. Also when switching from the
                 * allow-downgrade mode to full DNSSEC mode, flush it too. */
                if (l->unicast_scope)
                        dns_cache_flush(&l->unicast_scope->cache);
        }

        l->dnssec_mode = mode;
}

static int link_update_dnssec_mode(Link *l) {
        _cleanup_free_ char *m = NULL;
        DnssecMode mode;
        int r;

        assert(l);

        r = sd_network_link_get_dnssec(l->ifindex, &m);
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        mode = dnssec_mode_from_string(m);
        if (mode < 0) {
                r = -EINVAL;
                goto clear;
        }

        link_set_dnssec_mode(l, mode);

        return 0;

clear:
        l->dnssec_mode = _DNSSEC_MODE_INVALID;
        return r;
}

static int link_update_dnssec_negative_trust_anchors(Link *l) {
        _cleanup_strv_free_ char **ntas = NULL;
        _cleanup_set_free_free_ Set *ns = NULL;
        char **i;
        int r;

        assert(l);

        r = sd_network_link_get_dnssec_negative_trust_anchors(l->ifindex, &ntas);
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        ns = set_new(&dns_name_hash_ops);
        if (!ns)
                return -ENOMEM;

        STRV_FOREACH(i, ntas) {
                r = set_put_strdup(ns, *i);
                if (r < 0)
                        return r;
        }

        set_free_free(l->dnssec_negative_trust_anchors);
        l->dnssec_negative_trust_anchors = ns;
        ns = NULL;

        return 0;

clear:
        l->dnssec_negative_trust_anchors = set_free_free(l->dnssec_negative_trust_anchors);
        return r;
}

static int link_update_search_domain_one(Link *l, const char *name, bool route_only) {
        DnsSearchDomain *d;
        int r;

        r = dns_search_domain_find(l->search_domains, name, &d);
        if (r < 0)
                return r;
        if (r > 0)
                dns_search_domain_move_back_and_unmark(d);
        else {
                r = dns_search_domain_new(l->manager, &d, DNS_SEARCH_DOMAIN_LINK, l, name);
                if (r < 0)
                        return r;
        }

        d->route_only = route_only;
        return 0;
}

static int link_update_search_domains(Link *l) {
        _cleanup_strv_free_ char **sdomains = NULL, **rdomains = NULL;
        char **i;
        int r, q;

        assert(l);

        r = sd_network_link_get_search_domains(l->ifindex, &sdomains);
        if (r < 0 && r != -ENODATA)
                goto clear;

        q = sd_network_link_get_route_domains(l->ifindex, &rdomains);
        if (q < 0 && q != -ENODATA) {
                r = q;
                goto clear;
        }

        if (r == -ENODATA && q == -ENODATA) {
                /* networkd knows nothing about this interface, and that's fine. */
                r = 0;
                goto clear;
        }

        dns_search_domain_mark_all(l->search_domains);

        STRV_FOREACH(i, sdomains) {
                r = link_update_search_domain_one(l, *i, false);
                if (r < 0)
                        goto clear;
        }

        STRV_FOREACH(i, rdomains) {
                r = link_update_search_domain_one(l, *i, true);
                if (r < 0)
                        goto clear;
        }

        dns_search_domain_unlink_marked(l->search_domains);
        return 0;

clear:
        dns_search_domain_unlink_all(l->search_domains);
        return r;
}

static int link_is_unmanaged(Link *l) {
        _cleanup_free_ char *state = NULL;
        int r;

        assert(l);

        r = sd_network_link_get_setup_state(l->ifindex, &state);
        if (r == -ENODATA)
                return 1;
        if (r < 0)
                return r;

        return STR_IN_SET(state, "pending", "unmanaged");
}

static void link_read_settings(Link *l) {
        int r;

        assert(l);

        /* Read settings from networkd, except when networkd is not managing this interface. */

        r = link_is_unmanaged(l);
        if (r < 0) {
                log_warning_errno(r, "Failed to determine whether interface %s is managed: %m", l->name);
                return;
        }
        if (r > 0) {

                /* If this link used to be managed, but is now unmanaged, flush all our settings -- but only once. */
                if (l->is_managed)
                        link_flush_settings(l);

                l->is_managed = false;
                return;
        }

        l->is_managed = true;

        r = link_update_dns_servers(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read DNS servers for interface %s, ignoring: %m", l->name);

        r = link_update_llmnr_support(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read LLMNR support for interface %s, ignoring: %m", l->name);

        r = link_update_mdns_support(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read mDNS support for interface %s, ignoring: %m", l->name);

        r = link_update_dnssec_mode(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read DNSSEC mode for interface %s, ignoring: %m", l->name);

        r = link_update_dnssec_negative_trust_anchors(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read DNSSEC negative trust anchors for interface %s, ignoring: %m", l->name);

        r = link_update_search_domains(l);
        if (r < 0)
                log_warning_errno(r, "Failed to read search domains for interface %s, ignoring: %m", l->name);
}

int link_update_monitor(Link *l) {
        assert(l);

        link_read_settings(l);
        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return 0;
}

bool link_relevant(Link *l, int family, bool local_multicast) {
        _cleanup_free_ char *state = NULL;
        LinkAddress *a;

        assert(l);

        /* A link is relevant for local multicast traffic if it isn't a loopback or pointopoint device, has a link
         * beat, can do multicast and has at least one link-local (or better) IP address.
         *
         * A link is relevant for non-multicast traffic if it isn't a loopback device, has a link beat, and has at
         * least one routable address.*/

        if (l->flags & (IFF_LOOPBACK|IFF_DORMANT))
                return false;

        if ((l->flags & (IFF_UP|IFF_LOWER_UP)) != (IFF_UP|IFF_LOWER_UP))
                return false;

        if (local_multicast) {
                if (l->flags & IFF_POINTOPOINT)
                        return false;

                if ((l->flags & IFF_MULTICAST) != IFF_MULTICAST)
                        return false;
        }

        /* Check kernel operstate
         * https://www.kernel.org/doc/Documentation/networking/operstates.txt */
        if (!IN_SET(l->operstate, IF_OPER_UNKNOWN, IF_OPER_UP))
                return false;

        (void) sd_network_link_get_operational_state(l->ifindex, &state);
        if (state && !STR_IN_SET(state, "unknown", "degraded", "routable"))
                return false;

        LIST_FOREACH(addresses, a, l->addresses)
                if ((family == AF_UNSPEC || a->family == family) && link_address_relevant(a, local_multicast))
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

        if (s)
                log_info("Switching to DNS server %s for interface %s.", dns_server_string(s), l->name);

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

DnssecMode link_get_dnssec_mode(Link *l) {
        assert(l);

        if (l->dnssec_mode != _DNSSEC_MODE_INVALID)
                return l->dnssec_mode;

        return manager_get_dnssec_mode(l->manager);
}

bool link_dnssec_supported(Link *l) {
        DnsServer *server;

        assert(l);

        if (link_get_dnssec_mode(l) == DNSSEC_NO)
                return false;

        server = link_get_dns_server(l);
        if (server)
                return dns_server_dnssec_supported(server);

        return true;
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
                    link_address_relevant(a, true) &&
                    a->link->llmnr_ipv4_scope &&
                    a->link->llmnr_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->llmnr_support == RESOLVE_SUPPORT_YES) {

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

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_address_rr, DNSSEC_NO, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add A record to LLMNR zone: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_ptr_rr, DNSSEC_NO, false);
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
                    link_address_relevant(a, true) &&
                    a->link->llmnr_ipv6_scope &&
                    a->link->llmnr_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->llmnr_support == RESOLVE_SUPPORT_YES) {

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

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_address_rr, DNSSEC_NO, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add AAAA record to LLMNR zone: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_ptr_rr, DNSSEC_NO, false);
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

bool link_address_relevant(LinkAddress *a, bool local_multicast) {
        assert(a);

        if (a->flags & (IFA_F_DEPRECATED|IFA_F_TENTATIVE))
                return false;

        if (a->scope >= (local_multicast ? RT_SCOPE_HOST : RT_SCOPE_LINK))
                return false;

        return true;
}
