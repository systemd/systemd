/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "hashmap.h"
#include "resolved-dnssd.h"
#include "resolved-dnssd-bus.h"
#include "resolved-manager.h"
#include "strv.h"

int bus_dnssd_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        DnssdRegisteredService *s = ASSERT_PTR(userdata);
        Manager *m;
        int r;

        assert(message);

        m = s->manager;

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.resolve1.unregister-service",
                        /* details= */ NULL,
                        /* good_user= */ s->originator,
                        /* flags= */ 0,
                        &m->polkit_registry,
                        /* ret_admin= */ NULL,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        dnssd_registered_service_unregister(s);

        return sd_bus_reply_method_return(message, NULL);
}

static int dnssd_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DnssdRegisteredService *service;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/resolve1/dnssd", &name);
        if (r <= 0)
                return 0;

        service = hashmap_get(m->dnssd_registered_services, name);
        if (!service)
                return 0;

        *found = service;
        return 1;
}

static int dnssd_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DnssdRegisteredService *service;
        unsigned c = 0;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        l = new0(char*, hashmap_size(m->dnssd_registered_services) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(service, m->dnssd_registered_services) {
                char *p;

                r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", service->id, &p);
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
