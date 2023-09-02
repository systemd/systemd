/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "dhcp6-client-internal.h"
#include "dhcp6-protocol.h"
#include "networkd-dhcp6-bus.h"
#include "networkd-link-bus.h"
#include "networkd-manager.h"
#include "string-table.h"
#include "strv.h"

static int property_get_dhcp6_client_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = ASSERT_PTR(userdata);
        sd_dhcp6_client *c;

        assert(reply);

        c = l->dhcp6_client;
        if (!c)
                return sd_bus_message_append(reply, "s", "disabled");

        return sd_bus_message_append(reply, "s", dhcp6_state_to_string(dhcp6_client_get_state(c)));
}

static int dhcp6_client_emit_changed(Link *link, const char *property, ...) {
        _cleanup_free_ char *path = NULL;
        char **l;

        assert(link);

        if (sd_bus_is_ready(link->manager->bus) <= 0)
                return 0;

        path = link_bus_path(link);
        if (!path)
                return log_oom();

        l = strv_from_stdarg_alloca(property);

        return sd_bus_emit_properties_changed_strv(
                        link->manager->bus,
                        path,
                        "org.freedesktop.network1.DHCPv6Client",
                        l);
}

void dhcp6_client_callback_bus(sd_dhcp6_client *c, int event, void *userdata) {
        Link *l = ASSERT_PTR(userdata);

        dhcp6_client_emit_changed(l, "State", NULL);
}

static const sd_bus_vtable dhcp6_client_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("State", "s", property_get_dhcp6_client_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation dhcp6_client_object = {
        "/org/freedesktop/network1/link",
        "org.freedesktop.network1.DHCPv6Client",
        .fallback_vtables = BUS_FALLBACK_VTABLES({dhcp6_client_vtable, link_object_find}),
        .node_enumerator = link_node_enumerator,
};
