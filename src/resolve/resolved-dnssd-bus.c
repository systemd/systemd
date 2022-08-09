/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-polkit.h"
#include "missing_capability.h"
#include "resolved-dnssd-bus.h"
#include "resolved-dnssd.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "strv.h"
#include "user-util.h"

int bus_dnssd_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        DnssdService *s = ASSERT_PTR(userdata);
        Manager *m;
        Link *l;
        int r;

        assert(message);

        m = s->manager;

        r = bus_verify_polkit_async(message, CAP_SYS_ADMIN,
                                    "org.freedesktop.resolve1.unregister-service",
                                    NULL, false, s->originator,
                                    &m->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        HASHMAP_FOREACH(l, m->links) {
                if (l->mdns_ipv4_scope) {
                        r = dns_scope_announce(l->mdns_ipv4_scope, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to send goodbye messages in IPv4 scope: %m");

                        dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, s->ptr_rr);
                        dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, s->srv_rr);
                        LIST_FOREACH(items, txt_data, s->txt_data_items)
                                dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, txt_data->rr);
                }

                if (l->mdns_ipv6_scope) {
                        r = dns_scope_announce(l->mdns_ipv6_scope, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to send goodbye messages in IPv6 scope: %m");

                        dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, s->ptr_rr);
                        dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, s->srv_rr);
                        LIST_FOREACH(items, txt_data, s->txt_data_items)
                                dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, txt_data->rr);
                }
        }

        dnssd_service_free(s);

        manager_refresh_rrs(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int dnssd_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DnssdService *service;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/resolve1/dnssd", &name);
        if (r <= 0)
                return 0;

        service = hashmap_get(m->dnssd_services, name);
        if (!service)
                return 0;

        *found = service;
        return 1;
}

static int dnssd_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DnssdService *service;
        unsigned c = 0;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        l = new0(char*, hashmap_size(m->dnssd_services) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(service, m->dnssd_services) {
                char *p;

                r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", service->name, &p);
                if (r < 0)
                        return r;

                l[c++] = p;
        }

        l[c] = NULL;
        *nodes = TAKE_PTR(l);

        return 1;
}

static const sd_bus_vtable dnssd_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("Unregister", NULL, NULL, bus_dnssd_method_unregister, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("Conflicted", NULL, 0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation dnssd_object = {
        "/org/freedesktop/resolve1/dnssd",
        "org.freedesktop.resolve1.DnssdService",
        .fallback_vtables = BUS_FALLBACK_VTABLES({dnssd_vtable, dnssd_object_find}),
        .node_enumerator = dnssd_node_enumerator,
};
