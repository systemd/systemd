/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, l->search_domains) {
                r = sd_bus_message_append(reply, "s", d->name);
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

const sd_bus_vtable link_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("ScopesMask", "t", property_get_scopes_mask, 0, 0),
        SD_BUS_PROPERTY("DNS", "a(iay)", property_get_dns, 0, 0),
        SD_BUS_PROPERTY("Domains", "as", property_get_domains, 0, 0),
        SD_BUS_PROPERTY("LLMNR", "s", property_get_resolve_support, offsetof(Link, llmnr_support), 0),
        SD_BUS_PROPERTY("MulticastDNS", "s", property_get_resolve_support, offsetof(Link, mdns_support), 0),
        SD_BUS_PROPERTY("DNSSEC", "s", property_get_dnssec_mode, offsetof(Link, dnssec_mode), 0),
        SD_BUS_PROPERTY("DNSSECNegativeTrustAnchors", "as", property_get_ntas, 0, 0),

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
