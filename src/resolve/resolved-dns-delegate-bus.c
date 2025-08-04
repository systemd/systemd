/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "bus-object.h"
#include "hashmap.h"
#include "resolved-bus.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-delegate-bus.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-manager.h"
#include "strv.h"

static int property_get_dns(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        DnsDelegate *d = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(iiayqs)");
        if (r < 0)
                return r;

        LIST_FOREACH(servers, s, d->dns_servers) {
                r = bus_dns_server_append(reply, s, /* with_ifindex= */ true, /* extended= */ true);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_current_dns_server(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        DnsDelegate *d = ASSERT_PTR(userdata);

        assert(reply);

        return bus_dns_server_append(reply, d->current_dns_server, /* with_ifindex= */ true, /* extended= */ true);
}

static int property_get_domains(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        DnsDelegate *delegate = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(sb)");
        if (r < 0)
                return r;

        LIST_FOREACH(domains, d, delegate->search_domains) {
                r = sd_bus_message_append(reply, "(sb)", d->name, d->route_only);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int dns_delegate_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        _cleanup_free_ char *e = NULL;
        if (sd_bus_path_decode(path, "/org/freedesktop/resolve1/dns_delegate", &e) <= 0)
                return 0;

        DnsDelegate *d = hashmap_get(m->delegates, e);
        if (!d)
                return 0;

        *found = d;
        return 1;
}

char* dns_delegate_bus_path(const DnsDelegate *d) {
        char *p;

        assert(d);

        if (sd_bus_path_encode("/org/freedesktop/resolve1/dns_delegate", d->id, &p) < 0)
                return NULL;

        return p;
}

static int dns_delegate_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        _cleanup_strv_free_ char **l = NULL;
        DnsDelegate *d;
        HASHMAP_FOREACH(d, m->delegates) {
                _cleanup_free_ char *p = NULL;

                p = dns_delegate_bus_path(d);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, TAKE_PTR(p));
                if (r < 0)
                        return r;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}

static const sd_bus_vtable dns_delegate_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("DNS", "a(iiayqs)", property_get_dns, 0, 0),
        SD_BUS_PROPERTY("CurrentDNSServer", "(iiayqs)", property_get_current_dns_server, 0, 0),
        SD_BUS_PROPERTY("Domains", "a(sb)", property_get_domains, 0, 0),
        SD_BUS_PROPERTY("DefaultRoute", "b", bus_property_get_tristate, offsetof(DnsDelegate, default_route), 0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation dns_delegate_object = {
        "/org/freedesktop/resolve1/dns_delegate",
        "org.freedesktop.resolve1.DnsDelegate",
        .fallback_vtables = BUS_FALLBACK_VTABLES({dns_delegate_vtable, dns_delegate_object_find}),
        .node_enumerator = dns_delegate_node_enumerator,
};
