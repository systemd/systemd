/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Tom Gundersen

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

#include "bus-util.h"
#include "strv.h"

#include "networkd.h"
#include "networkd-link.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_operational_state, link_operstate, LinkOperationalState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_administrative_state, link_state, LinkState);

const sd_bus_vtable link_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("OperationalState", "s", property_get_operational_state, offsetof(Link, operstate), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AdministrativeState", "s", property_get_administrative_state, offsetof(Link, state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

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
        Link *link;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(m);
        assert(nodes);

        HASHMAP_FOREACH(link, m->links, i) {
                char *p;

                p = link_bus_path(link);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = l;
        l = NULL;

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
        if (r < 0)
                return 0;

        r = safe_atoi(identifier, &ifindex);
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
