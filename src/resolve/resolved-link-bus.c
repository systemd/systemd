/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "alloc-util.h"
#include "bus-util.h"
#include "parse-util.h"
#include "resolve-util.h"
#include "resolved-bus.h"
#include "resolved-link-bus.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_resolve_support, resolve_support, ResolveSupport);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_dnssec_mode, dnssec_mode, DnssecMode);

static int property_get_dns(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = userdata;
        DnsServer *s;
        int r;

        assert(reply);
        assert(l);

        r = sd_bus_message_open_container(reply, 'a', "(iay)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, l->dns_servers) {
                r = bus_dns_server_append(reply, s, false);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_domains(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = userdata;
        DnsSearchDomain *d;
        int r;

        assert(reply);
        assert(l);

        r = sd_bus_message_open_container(reply, 'a', "(sb)");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, l->search_domains) {
                r = sd_bus_message_append(reply, "(sb)", d->name, d->route_only);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_scopes_mask(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = userdata;
        uint64_t mask;

        assert(reply);
        assert(l);

        mask =  (l->unicast_scope ? SD_RESOLVED_DNS : 0) |
                (l->llmnr_ipv4_scope ? SD_RESOLVED_LLMNR_IPV4 : 0) |
                (l->llmnr_ipv6_scope ? SD_RESOLVED_LLMNR_IPV6 : 0) |
                (l->mdns_ipv4_scope ? SD_RESOLVED_MDNS_IPV4 : 0) |
                (l->mdns_ipv6_scope ? SD_RESOLVED_MDNS_IPV6 : 0);

        return sd_bus_message_append(reply, "t", mask);
}

static int property_get_ntas(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = userdata;
        const char *name;
        Iterator i;
        int r;

        assert(reply);
        assert(l);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(name, l->dnssec_negative_trust_anchors, i) {
                r = sd_bus_message_append(reply, "s", name);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_dnssec_supported(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = userdata;

        assert(reply);
        assert(l);

        return sd_bus_message_append(reply, "b", link_dnssec_supported(l));
}

int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ struct in_addr_data *dns = NULL;
        size_t allocated = 0, n = 0;
        Link *l = userdata;
        unsigned i;
        int r;

        assert(message);
        assert(l);

        r = sd_bus_message_enter_container(message, 'a', "(iay)");
        if (r < 0)
                return r;

        for (;;) {
                int family;
                size_t sz;
                const void *d;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_enter_container(message, 'r', "iay");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(message, "i", &family);
                if (r < 0)
                        return r;

                if (!IN_SET(family, AF_INET, AF_INET6))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

                r = sd_bus_message_read_array(message, 'y', &d, &sz);
                if (r < 0)
                        return r;
                if (sz != FAMILY_ADDRESS_SIZE(family))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address size");

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(dns, allocated, n+1))
                        return -ENOMEM;

                dns[n].family = family;
                memcpy(&dns[n].address, d, sz);
                n++;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        dns_server_mark_all(l->dns_servers);

        for (i = 0; i < n; i++) {
                DnsServer *s;

                s = dns_server_find(l->dns_servers, dns[i].family, &dns[i].address);
                if (s)
                        dns_server_move_back_and_unmark(s);
                else {
                        r = dns_server_new(l->manager, NULL, DNS_SERVER_LINK, l, dns[i].family, &dns[i].address);
                        if (r < 0)
                                goto clear;
                }

        }

        dns_server_unlink_marked(l->dns_servers);
        link_allocate_scopes(l);

        return sd_bus_reply_method_return(message, NULL);

clear:
        dns_server_unlink_all(l->dns_servers);
        return r;
}

int bus_link_method_set_domains(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        int r;

        assert(message);
        assert(l);

        r = sd_bus_message_enter_container(message, 'a', "(sb)");
        if (r < 0)
                return r;

        for (;;) {
                const char *name;
                int route_only;

                r = sd_bus_message_read(message, "(sb)", &name, &route_only);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = dns_name_is_valid(name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid search domain %s", name);
                if (!route_only && dns_name_is_root(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Root domain is not suitable as search domain");
        }

        dns_search_domain_mark_all(l->search_domains);

        r = sd_bus_message_rewind(message, false);
        if (r < 0)
                return r;

        for (;;) {
                DnsSearchDomain *d;
                const char *name;
                int route_only;

                r = sd_bus_message_read(message, "(sb)", &name, &route_only);
                if (r < 0)
                        goto clear;
                if (r == 0)
                        break;

                r = dns_search_domain_find(l->search_domains, name, &d);
                if (r < 0)
                        goto clear;

                if (r > 0)
                        dns_search_domain_move_back_and_unmark(d);
                else {
                        r = dns_search_domain_new(l->manager, &d, DNS_SEARCH_DOMAIN_LINK, l, name);
                        if (r < 0)
                                goto clear;
                }

                d->route_only = route_only;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                goto clear;

        dns_search_domain_unlink_marked(l->search_domains);
        return sd_bus_reply_method_return(message, NULL);

clear:
        dns_search_domain_unlink_all(l->search_domains);
        return r;
}

int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        ResolveSupport mode;
        const char *llmnr;
        int r;

        assert(message);
        assert(l);

        r = sd_bus_message_read(message, "s", &llmnr);
        if (r < 0)
                return r;

        if (isempty(llmnr))
                mode = RESOLVE_SUPPORT_YES;
        else {
                mode = resolve_support_from_string(llmnr);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid LLMNR setting: %s", llmnr);
        }

        l->llmnr_support = mode;
        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        ResolveSupport mode;
        const char *mdns;
        int r;

        assert(message);
        assert(l);

        r = sd_bus_message_read(message, "s", &mdns);
        if (r < 0)
                return r;

        if (isempty(mdns))
                mode = RESOLVE_SUPPORT_NO;
        else {
                mode = resolve_support_from_string(mdns);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid MulticastDNS setting: %s", mdns);
        }

        l->mdns_support = mode;
        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        const char *dnssec;
        DnssecMode mode;
        int r;

        assert(message);
        assert(l);

        r = sd_bus_message_read(message, "s", &dnssec);
        if (r < 0)
                return r;

        if (isempty(dnssec))
                mode = _DNSSEC_MODE_INVALID;
        else {
                mode = dnssec_mode_from_string(dnssec);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid DNSSEC setting: %s", dnssec);
        }

        link_set_dnssec_mode(l, mode);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_set_free_free_ Set *ns = NULL;
        _cleanup_free_ char **ntas = NULL;
        Link *l = userdata;
        int r;
        char **i;

        assert(message);
        assert(l);

        r = sd_bus_message_read_strv(message, &ntas);
        if (r < 0)
                return r;

        STRV_FOREACH(i, ntas) {
                r = dns_name_is_valid(*i);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid negative trust anchor domain: %s", *i);
        }

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

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_revert(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;

        assert(message);
        assert(l);

        link_flush_settings(l);
        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable link_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("ScopesMask", "t", property_get_scopes_mask, 0, 0),
        SD_BUS_PROPERTY("DNS", "a(iay)", property_get_dns, 0, 0),
        SD_BUS_PROPERTY("Domains", "a(sb)", property_get_domains, 0, 0),
        SD_BUS_PROPERTY("LLMNR", "s", property_get_resolve_support, offsetof(Link, llmnr_support), 0),
        SD_BUS_PROPERTY("MulticastDNS", "s", property_get_resolve_support, offsetof(Link, mdns_support), 0),
        SD_BUS_PROPERTY("DNSSEC", "s", property_get_dnssec_mode, offsetof(Link, dnssec_mode), 0),
        SD_BUS_PROPERTY("DNSSECNegativeTrustAnchors", "as", property_get_ntas, 0, 0),
        SD_BUS_PROPERTY("DNSSECSupported", "b", property_get_dnssec_supported, 0, 0),

        SD_BUS_METHOD("SetDNS", "a(iay)", NULL, bus_link_method_set_dns_servers, 0),
        SD_BUS_METHOD("SetDomains", "a(sb)", NULL, bus_link_method_set_domains, 0),
        SD_BUS_METHOD("SetLLMNR", "s", NULL, bus_link_method_set_llmnr, 0),
        SD_BUS_METHOD("SetMulticastDNS", "s", NULL, bus_link_method_set_mdns, 0),
        SD_BUS_METHOD("SetDNSSEC", "s", NULL, bus_link_method_set_dnssec, 0),
        SD_BUS_METHOD("SetDNSSECNegativeTrustAnchors", "as", NULL, bus_link_method_set_dnssec_negative_trust_anchors, 0),
        SD_BUS_METHOD("Revert", NULL, NULL, bus_link_method_revert, 0),

        SD_BUS_VTABLE_END
};

int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *e = NULL;
        Manager *m = userdata;
        int ifindex;
        Link *link;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = sd_bus_path_decode(path, "/org/freedesktop/resolve1/link", &e);
        if (r <= 0)
                return 0;

        r = parse_ifindex(e, &ifindex);
        if (r < 0)
                return 0;

        link = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!link)
                return 0;

        *found = link;
        return 1;
}

char *link_bus_path(Link *link) {
        _cleanup_free_ char *ifindex = NULL;
        char *p;
        int r;

        assert(link);

        if (asprintf(&ifindex, "%i", link->ifindex) < 0)
                return NULL;

        r = sd_bus_path_encode("/org/freedesktop/resolve1/link", ifindex, &p);
        if (r < 0)
                return NULL;

        return p;
}

int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        Link *link;
        Iterator i;
        unsigned c = 0;

        assert(bus);
        assert(path);
        assert(m);
        assert(nodes);

        l = new0(char*, hashmap_size(m->links) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(link, m->links, i) {
                char *p;

                p = link_bus_path(link);
                if (!p)
                        return -ENOMEM;

                l[c++] = p;
        }

        l[c] = NULL;
        *nodes = l;
        l = NULL;

        return 1;
}
