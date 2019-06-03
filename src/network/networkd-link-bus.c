/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_operational_state, link_operstate, LinkOperationalState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_administrative_state, link_state, LinkState);

static int property_get_bit_rates(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *link = userdata;
        Manager *manager;
        double tx, rx, interval_sec;

        assert(bus);
        assert(reply);
        assert(userdata);

        manager = link->manager;

        if (!manager->use_speed_meter)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Speed meter is disabled.");

        if (manager->speed_meter_usec_old == 0)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Speed meter is not active.");

        if (!link->stats_updated)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Failed to measure bit-rates.");

        assert(manager->speed_meter_usec_new > manager->speed_meter_usec_old);
        interval_sec = (double) (manager->speed_meter_usec_new - manager->speed_meter_usec_old) / USEC_PER_SEC;

        if (link->stats_new.tx_bytes > link->stats_old.tx_bytes)
                tx = (link->stats_new.tx_bytes - link->stats_old.tx_bytes) / interval_sec;
        else
                tx = (UINT64_MAX - (link->stats_old.tx_bytes - link->stats_new.tx_bytes)) / interval_sec;

        if (link->stats_new.rx_bytes > link->stats_old.rx_bytes)
                rx = (link->stats_new.rx_bytes - link->stats_old.rx_bytes) / interval_sec;
        else
                rx = (UINT64_MAX - (link->stats_old.rx_bytes - link->stats_new.rx_bytes)) / interval_sec;

        return sd_bus_message_append(reply, "(dd)", tx, rx);
}

const sd_bus_vtable link_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("OperationalState", "s", property_get_operational_state, offsetof(Link, operstate), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AdministrativeState", "s", property_get_administrative_state, offsetof(Link, state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BitRates", "(dd)", property_get_bit_rates, 0, 0),

        SD_BUS_VTABLE_END
};

static char *link_bus_path(Link *link) {
        _cleanup_free_ char *ifindex = NULL;
        char *p;
        int r;

        assert(link);
        assert(link->ifindex > 0);

        if (asprintf(&ifindex, "%d", link->ifindex) < 0)
                return NULL;

        r = sd_bus_path_encode("/org/freedesktop/network1/link", ifindex, &p);
        if (r < 0)
                return NULL;

        return p;
}

int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned c = 0;
        Link *link;
        Iterator i;

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
        *nodes = TAKE_PTR(l);

        return 1;
}

int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *identifier = NULL;
        Manager *m = userdata;
        Link *link;
        int ifindex, r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(m);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/network1/link", &identifier);
        if (r <= 0)
                return 0;

        r = parse_ifindex(identifier, &ifindex);
        if (r < 0)
                return 0;

        r = link_get(m, ifindex, &link);
        if (r < 0)
                return 0;

        *found = link;

        return 1;
}

int link_send_changed(Link *link, const char *property, ...) {
        _cleanup_free_ char *p = NULL;
        char **l;

        assert(link);
        assert(link->manager);

        if (!link->manager->bus)
                return 0; /* replace with assert when we have kdbus */

        l = strv_from_stdarg_alloca(property);

        p = link_bus_path(link);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_properties_changed_strv(
                        link->manager->bus,
                        p,
                        "org.freedesktop.network1.Link",
                        l);
}
