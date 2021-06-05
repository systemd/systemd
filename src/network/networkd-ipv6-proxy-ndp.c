/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>

#include "netlink-util.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "socket-util.h"
#include "string-util.h"
#include "sysctl-util.h"

static int set_ipv6_proxy_ndp_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not add IPv6 proxy ndp address entry, ignoring");

        return 1;
}

/* send a request to the kernel to add a IPv6 Proxy entry to the neighbour table */
static int ipv6_proxy_ndp_address_configure(Link *link, const struct in6_addr *address) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        /* create new netlink message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH, link->ifindex, AF_INET6);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_flags(req, NTF_PROXY);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set neighbor flags: %m");

        r = sd_netlink_message_append_in6_addr(req, NDA_DST, address);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append NDA_DST attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, set_ipv6_proxy_ndp_address_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static bool ipv6_proxy_ndp_is_needed(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->ipv6_proxy_ndp >= 0)
                return link->network->ipv6_proxy_ndp;

        return !set_isempty(link->network->ipv6_proxy_ndp_addresses);
}

static int ipv6_proxy_ndp_set(Link *link) {
        bool v;
        int r;

        assert(link);

        if (!socket_ipv6_is_supported())
                return 0;

        v = ipv6_proxy_ndp_is_needed(link);

        r = sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "proxy_ndp", v);
        if (r < 0)
                return log_link_warning_errno(link, r, "Cannot configure proxy NDP for the interface, ignoring: %m");

        return v;
}

/* configure all ipv6 proxy ndp addresses */
int link_set_ipv6_proxy_ndp_addresses(Link *link) {
        struct in6_addr *address;
        int r;

        assert(link);
        assert(link->network);

        /* enable or disable proxy_ndp itself depending on whether ipv6_proxy_ndp_addresses are set or not */
        r = ipv6_proxy_ndp_set(link);
        if (r <= 0)
                return 0;

        SET_FOREACH(address, link->network->ipv6_proxy_ndp_addresses) {
                r = ipv6_proxy_ndp_address_configure(link, address);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_ipv6_proxy_ndp_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ struct in6_addr *address = NULL;
        Network *network = userdata;
        union in_addr_union buffer;
        int r;

        assert(filename);
        assert(rvalue);
        assert(network);

        if (isempty(rvalue)) {
                network->ipv6_proxy_ndp_addresses = set_free_free(network->ipv6_proxy_ndp_addresses);
                return 0;
        }

        r = in_addr_from_string(AF_INET6, rvalue, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse IPv6 proxy NDP address, ignoring: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(AF_INET6, &buffer)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "IPv6 proxy NDP address cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        address = newdup(struct in6_addr, &buffer.in6, 1);
        if (!address)
                return log_oom();

        r = set_ensure_put(&network->ipv6_proxy_ndp_addresses, &in6_addr_hash_ops, address);
        if (r < 0)
                return log_oom();
        if (r > 0)
                TAKE_PTR(address);

        return 0;
}
