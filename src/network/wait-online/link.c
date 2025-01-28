/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-network.h"

#include "alloc-util.h"
#include "dns-configuration.h"
#include "format-ifname.h"
#include "hashmap.h"
#include "link.h"
#include "manager.h"
#include "string-util.h"
#include "strv.h"

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
                .dns_configuration = hashmap_remove(m->dns_configuration_by_link_index, INT_TO_PTR(ifindex)),
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

                STRV_FOREACH(n, l->altnames)
                        hashmap_remove(l->manager->links_by_name, *n);
        }

        dns_configuration_free(l->dns_configuration);

        free(l->state);
        free(l->ifname);
        strv_free(l->altnames);
        return mfree(l);
}

static int link_update_name(Link *l, sd_netlink_message *m) {
        char ifname_from_index[IF_NAMESIZE];
        const char *ifname;
        int r;

        assert(l);
        assert(l->manager);
        assert(m);

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r == -ENODATA)
                /* Hmm? But ok. */
                return 0;
        if (r < 0)
                return r;

        if (streq(ifname, l->ifname))
                return 0;

        /* The kernel sometimes sends wrong ifname change. Let's confirm the received name. */
        r = format_ifname(l->ifindex, ifname_from_index);
        if (r < 0)
                return r;

        if (!streq(ifname, ifname_from_index)) {
                log_link_debug(l, "New interface name '%s' received from the kernel does not correspond "
                               "with the name currently configured on the actual interface '%s'. Ignoring.",
                               ifname, ifname_from_index);
                return 0;
        }

        hashmap_remove(l->manager->links_by_name, l->ifname);

        r = free_and_strdup(&l->ifname, ifname);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&l->manager->links_by_name, &string_hash_ops, l->ifname, l);
        if (r < 0)
                return r;

        return 0;
}

static int link_update_altnames(Link *l, sd_netlink_message *m) {
        _cleanup_strv_free_ char **altnames = NULL;
        int r;

        assert(l);
        assert(l->manager);
        assert(m);

        r = sd_netlink_message_read_strv(m, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &altnames);
        if (r == -ENODATA)
                /* The message does not have IFLA_PROP_LIST container attribute. It does not mean the
                 * interface has no alternative name. */
                return 0;
        if (r < 0)
                return r;

        if (strv_equal(altnames, l->altnames))
                return 0;

        STRV_FOREACH(n, l->altnames)
                hashmap_remove(l->manager->links_by_name, *n);

        strv_free_and_replace(l->altnames, altnames);

        STRV_FOREACH(n, l->altnames) {
                r = hashmap_ensure_put(&l->manager->links_by_name, &string_hash_ops, *n, l);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_update_rtnl(Link *l, sd_netlink_message *m) {
        int r;

        assert(l);
        assert(l->manager);
        assert(m);

        r = sd_rtnl_message_link_get_flags(m, &l->flags);
        if (r < 0)
                return r;

        r = link_update_name(l, m);
        if (r < 0)
                return r;

        r = link_update_altnames(l, m);
        if (r < 0)
                return r;

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
