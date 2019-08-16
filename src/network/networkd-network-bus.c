/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "networkd-manager.h"
#include "networkd-network-bus.h"
#include "string-util.h"
#include "strv.h"

static int property_get_ether_addrs(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        char buf[ETHER_ADDR_TO_STRING_MAX];
        const struct ether_addr *p;
        Iterator i;
        Set *s;
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        s = *(Set **) userdata;

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(p, s, i) {
                r = sd_bus_message_append(reply, "s", ether_addr_to_string(p, buf));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable network_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Description", "s", NULL, offsetof(Network, description), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SourcePath", "s", NULL, offsetof(Network, filename), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MatchMAC", "as", property_get_ether_addrs, offsetof(Network, match_mac), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MatchPath", "as", NULL, offsetof(Network, match_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MatchDriver", "as", NULL, offsetof(Network, match_driver), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MatchType", "as", NULL, offsetof(Network, match_type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MatchName", "as", NULL, offsetof(Network, match_name), SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_VTABLE_END
};

static char *network_bus_path(Network *network) {
        _cleanup_free_ char *name = NULL;
        char *networkname, *d, *path;
        int r;

        assert(network);
        assert(network->filename);

        name = strdup(network->filename);
        if (!name)
                return NULL;

        networkname = basename(name);

        d = strrchr(networkname, '.');
        if (!d)
                return NULL;

        assert(streq(d, ".network"));

        *d = '\0';

        r = sd_bus_path_encode("/org/freedesktop/network1/network", networkname, &path);
        if (r < 0)
                return NULL;

        return path;
}

int network_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        Network *network;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(m);
        assert(nodes);

        ORDERED_HASHMAP_FOREACH(network, m->networks, i) {
                char *p;

                p = network_bus_path(network);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}

int network_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Network *network;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(m);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/network1/network", &name);
        if (r < 0)
                return 0;

        r = network_get_by_name(m, name, &network);
        if (r < 0)
                return 0;

        *found = network;

        return 1;
}
