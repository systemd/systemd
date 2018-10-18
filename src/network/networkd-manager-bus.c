/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-util.h"
#include "networkd-manager.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_operational_state, link_operstate, LinkOperationalState);

static int bus_property_get_links(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        Link *link;
        Iterator i;
        int r;

        assert(reply);
        assert(m);

        r = sd_bus_message_open_container(reply, 'a', "(iso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(link, m->links, i) {
                _cleanup_free_ char *p = NULL;

                if (link->ifindex <= 0 || !link->ifname)
                        continue;

                p = link_bus_path(link);
                if (!path)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(iso)", link->ifindex, link->ifname, p);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("OperationalState", "s", property_get_operational_state, offsetof(Manager, operational_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Links", "a(iso)", bus_property_get_links, 0, 0),

        SD_BUS_VTABLE_END
};

int manager_send_changed(Manager *manager, const char *property, ...) {
        char **l;

        assert(manager);

        if (!manager->bus)
                return 0; /* replace by assert when we have kdbus */

        l = strv_from_stdarg_alloca(property);

        return sd_bus_emit_properties_changed_strv(
                        manager->bus,
                        "/org/freedesktop/network1",
                        "org.freedesktop.network1.Manager",
                        l);
}
