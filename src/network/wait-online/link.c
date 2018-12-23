/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-network.h"

#include "alloc-util.h"
#include "hashmap.h"
#include "link.h"
#include "manager.h"
#include "string-util.h"

int link_new(Manager *m, Link **ret, int ifindex, const char *ifname) {
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);

        r = hashmap_ensure_allocated(&m->links, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->links_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        l = new0(Link, 1);
        if (!l)
                return -ENOMEM;

        l->manager = m;

        l->ifname = strdup(ifname);
        if (!l->ifname)
                return -ENOMEM;

        r = hashmap_put(m->links_by_name, l->ifname, l);
        if (r < 0)
                return r;

        l->ifindex = ifindex;

        r = hashmap_put(m->links, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        if (ret)
                *ret = l;
        l = NULL;

        return 0;
}

Link *link_free(Link *l) {

        if (!l)
                return NULL;

        if (l->manager) {
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));
                hashmap_remove(l->manager->links_by_name, l->ifname);
        }

        free(l->ifname);
        return mfree(l);
}

int link_update_rtnl(Link *l, sd_netlink_message *m) {
        const char *ifname;
        int r;

        assert(l);
        assert(l->manager);
        assert(m);

        r = sd_rtnl_message_link_get_flags(m, &l->flags);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r < 0)
                return r;

        if (!streq(l->ifname, ifname)) {
                char *new_ifname;

                new_ifname = strdup(ifname);
                if (!new_ifname)
                        return -ENOMEM;

                hashmap_remove(l->manager->links_by_name, l->ifname);
                free(l->ifname);
                l->ifname = new_ifname;

                r = hashmap_put(l->manager->links_by_name, l->ifname, l);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_update_monitor(Link *l) {
        assert(l);

        l->required_for_online = sd_network_link_get_required_for_online(l->ifindex) != 0;

        l->operational_state = mfree(l->operational_state);

        sd_network_link_get_operational_state(l->ifindex, &l->operational_state);

        l->state = mfree(l->state);

        sd_network_link_get_setup_state(l->ifindex, &l->state);

        return 0;
}
