/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-dhcp-client.h"

#include "alloc-util.h"
#include "bus-object.h"
#include "dhcp-client-internal.h"
#include "networkd-dhcp4-bus.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-manager.h"

static int property_get_dhcp_client_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *l = ASSERT_PTR(userdata);
        sd_dhcp_client *c;

        assert(reply);

        c = l->dhcp_client;
        if (!c)
                return sd_bus_message_append(reply, "s", "disabled");

        return sd_bus_message_append(reply, "s", dhcp_state_to_string(dhcp_client_get_state(c)));
}

static int dhcp_client_emit_changed(Link *link, char **properties) {
        _cleanup_free_ char *path = NULL;

        assert(link);

        if (sd_bus_is_ready(link->manager->bus) <= 0)
                return 0;

        path = link_bus_path(link);
        if (!path)
                return log_oom();

        return sd_bus_emit_properties_changed_strv(
                        link->manager->bus,
                        path,
                        "org.freedesktop.network1.DHCPv4Client",
                        properties);
}

int dhcp_client_callback_bus(sd_dhcp_client *c, int event, void *userdata) {
        Link *l = ASSERT_PTR(userdata);

        return dhcp_client_emit_changed(l, STRV_MAKE("State"));
}

static const sd_bus_vtable dhcp_client_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("State", "s", property_get_dhcp_client_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation dhcp_client_object = {
        "/org/freedesktop/network1/link",
        "org.freedesktop.network1.DHCPv4Client",
        .fallback_vtables = BUS_FALLBACK_VTABLES({dhcp_client_vtable, link_object_find}),
        .node_enumerator = link_node_enumerator,
};
