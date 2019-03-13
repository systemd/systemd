/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-network.h"

#include "alloc-util.h"
#include "hashmap.h"
#include "link.h"
#include "manager.h"
#include "string-util.h"

int link_new(Manager *m, Link **ret, int ifindex, const char *ifname) {
        _cleanup_(link_freep) Link *l = NULL;
        _cleanup_free_ char *n = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);

        r = hashmap_ensure_allocated(&m->links, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->links_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        n = strdup(ifname);
        if (!n)
                return -ENOMEM;

        l = new(Link, 1);
        if (!l)
                return -ENOMEM;

        *l = (Link) {
                .manager = m,
                .ifname = TAKE_PTR(n),
                .ifindex = ifindex,
                .required_operstate = LINK_OPERSTATE_DEGRADED,
        };

        r = hashmap_put(m->links_by_name, l->ifname, l);
        if (r < 0)
                return r;

        r = hashmap_put(m->links, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        if (ret)
                *ret = l;

        TAKE_PTR(l);
        return 0;
}

Link *link_free(Link *l) {

        if (!l)
                return NULL;

        if (l->manager) {
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));
                hashmap_remove(l->manager->links_by_name, l->ifname);
        }

        free(l->state);
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

                assert_se(hashmap_remove(l->manager->links_by_name, l->ifname) == l);
                free_and_replace(l->ifname, new_ifname);

                r = hashmap_put(l->manager->links_by_name, l->ifname, l);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_update_monitor(Link *l) {
        _cleanup_free_ char *operstate = NULL, *required_operstate = NULL, *state = NULL;
        LinkOperationalState s;
        int r, ret = 0;

        assert(l);
        assert(l->ifname);

        r = sd_network_link_get_required_for_online(l->ifindex);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to determine whether the link is required for online or not, "
                                           "ignoring: %m");
        else
                l->required_for_online = r > 0;

        r = sd_network_link_get_required_operstate_for_online(l->ifindex, &required_operstate);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get required operational state, ignoring: %m");
        else {
                s = link_operstate_from_string(required_operstate);
                if (s < 0)
                        ret = log_link_debug_errno(l, SYNTHETIC_ERRNO(EINVAL),
                                                   "Failed to parse required operational state, ignoring: %m");
                else
                        l->required_operstate = s;
        }

        r = sd_network_link_get_operational_state(l->ifindex, &operstate);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get operational state, ignoring: %m");
        else {
                s = link_operstate_from_string(operstate);
                if (s < 0)
                        ret = log_link_debug_errno(l, SYNTHETIC_ERRNO(EINVAL),
                                                   "Failed to parse operational state, ignoring: %m");
                else
                        l->operational_state = s;
        }

        r = sd_network_link_get_setup_state(l->ifindex, &state);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get setup state, ignoring: %m");
        else
                free_and_replace(l->state, state);

        return ret;
}
