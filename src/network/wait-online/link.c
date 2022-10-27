/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
        assert(ifname);

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
                .required_operstate = LINK_OPERSTATE_RANGE_DEFAULT,
        };

        r = hashmap_ensure_put(&m->links_by_index, NULL, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&m->links_by_name, &string_hash_ops, l->ifname, l);
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
                hashmap_remove(l->manager->links_by_index, INT_TO_PTR(l->ifindex));
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
        _cleanup_free_ char *required_operstate = NULL, *required_family = NULL,
                *ipv4_address_state = NULL, *ipv6_address_state = NULL, *state = NULL;
        int r, ret = 0;

        assert(l);
        assert(l->ifname);

        r = sd_network_link_get_required_for_online(l->ifindex);
        if (r < 0 && r != -ENODATA)
                ret = log_link_debug_errno(l, r, "Failed to determine whether the link is required for online or not, "
                                           "assuming required: %m");
        l->required_for_online = r != 0;

        r = sd_network_link_get_required_operstate_for_online(l->ifindex, &required_operstate);
        if (r < 0 && r != -ENODATA)
                ret = log_link_debug_errno(l, r, "Failed to get required operational state, ignoring: %m");

        if (isempty(required_operstate))
                l->required_operstate = LINK_OPERSTATE_RANGE_DEFAULT;
        else {
                r = parse_operational_state_range(required_operstate, &l->required_operstate);
                if (r < 0)
                        ret = log_link_debug_errno(l, SYNTHETIC_ERRNO(EINVAL),
                                                   "Failed to parse required operational state, ignoring: %m");
        }

        r = network_link_get_operational_state(l->ifindex, &l->operational_state);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get operational state, ignoring: %m");

        r = sd_network_link_get_required_family_for_online(l->ifindex, &required_family);
        if (r < 0 && r != -ENODATA)
                ret = log_link_debug_errno(l, r, "Failed to get required address family, ignoring: %m");

        if (isempty(required_family))
                l->required_family = ADDRESS_FAMILY_NO;
        else {
                AddressFamily f;

                f = link_required_address_family_from_string(required_family);
                if (f < 0)
                        ret = log_link_debug_errno(l, f, "Failed to parse required address family, ignoring: %m");
                else
                        l->required_family = f;
        }

        r = sd_network_link_get_ipv4_address_state(l->ifindex, &ipv4_address_state);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get IPv4 address state, ignoring: %m");
        else {
                LinkAddressState s;

                s = link_address_state_from_string(ipv4_address_state);
                if (s < 0)
                        ret = log_link_debug_errno(l, s, "Failed to parse IPv4 address state, ignoring: %m");
                else
                        l->ipv4_address_state = s;
        }

        r = sd_network_link_get_ipv6_address_state(l->ifindex, &ipv6_address_state);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get IPv6 address state, ignoring: %m");
        else {
                LinkAddressState s;

                s = link_address_state_from_string(ipv6_address_state);
                if (s < 0)
                        ret = log_link_debug_errno(l, s, "Failed to parse IPv6 address state, ignoring: %m");
                else
                        l->ipv6_address_state = s;
        }

        r = sd_network_link_get_setup_state(l->ifindex, &state);
        if (r < 0)
                ret = log_link_debug_errno(l, r, "Failed to get setup state, ignoring: %m");
        else
                free_and_replace(l->state, state);

        return ret;
}
