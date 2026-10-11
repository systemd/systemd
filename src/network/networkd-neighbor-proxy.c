/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-netlink.h"

#include "in-addr-util.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor-proxy.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"

void network_adjust_neighbor_proxy(Network *network) {
        assert(network);

        struct in_addr_data *a;
        SET_FOREACH(a, network->neighbor_proxy_addresses) {
                switch (a->family) {
                case AF_INET6:
                        if (!socket_ipv6_is_supported()) {
                                log_warning("%s: Specified IPv6 proxy NDP address %s, but IPv6 is not supported by the kernel, ignoring.",
                                            network->filename, IN_ADDR_TO_STRING(a->family, &a->address));
                                free(set_remove(network->neighbor_proxy_addresses, a));
                                continue;
                        }

                        if (network->ipv6_proxy_ndp == 0) {
                                log_warning("%s: Specified IPv6 proxy NDP address %s, but IPv6ProxyNDP= is disabled, ignoring.",
                                            network->filename, IN_ADDR_TO_STRING(a->family, &a->address));
                                free(set_remove(network->neighbor_proxy_addresses, a));
                                continue;
                        }

                        /* IPv6 proxy NDP entry requires that proxy_ndp sysctl is enabled. */
                        network->ipv6_proxy_ndp = true;
                        break;

                case AF_INET:
                        /* IPv4 proxy ARP entry does NOT require that proxy_arp sysctl is enabled. */
                        break;

                default:
                        assert_not_reached();
                }
        }
}

static int neighbor_proxy_address_configure_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                struct in_addr_data *address) {

        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r,
                                               "Could not add neighbor proxy address entry, ignoring");

        if (link->static_neighbor_proxy_messages == 0) {
                log_link_debug(link, "Neighbor proxy addresses set.");
                link->static_neighbor_proxy_configured = true;
                link_check_ready(link);
        }

        return 1;
}

/* Send a request to the kernel to add a proxy entry to the neighbour table. */
static int neighbor_proxy_address_configure(const struct in_addr_data *address, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        /* create new netlink message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH, link->ifindex, address->family);
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_flags(m, NTF_PROXY);
        if (r < 0)
                return r;

        r = netlink_message_append_in_addr_union(m, NDA_DST, address->family, &address->address);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int neighbor_proxy_address_process_request(Request *req, Link *link, struct in_addr_data *address) {
        int r;

        assert(req);
        assert(link);
        assert(address);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = neighbor_proxy_address_configure(address, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure neighbor proxy address: %m");

        return 1;
}

int link_request_static_neighbor_proxy_addresses(Link *link) {
        struct in_addr_data *address;
        int r;

        assert(link);
        assert(link->network);

        link->static_neighbor_proxy_configured = false;

        SET_FOREACH(address, link->network->neighbor_proxy_addresses) {
                r = link_queue_request_safe(link, REQUEST_TYPE_NEIGHBOR_PROXY,
                                            address, NULL,
                                            in_addr_data_hash_func,
                                            in_addr_data_compare_func,
                                            neighbor_proxy_address_process_request,
                                            &link->static_neighbor_proxy_messages,
                                            neighbor_proxy_address_configure_handler,
                                            NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to request neighbor proxy address: %m");
        }

        if (link->static_neighbor_proxy_messages == 0) {
                link->static_neighbor_proxy_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting neighbor proxy addresses.");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

int config_parse_neighbor_proxy_address(
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

        Set **neighbor_proxy_addresses = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *neighbor_proxy_addresses = set_free(*neighbor_proxy_addresses);
                return 0;
        }

        struct in_addr_data a = {};
        r = in_addr_from_string_auto(rvalue, &a.family, &a.address);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (in_addr_is_null(a.family, &a.address)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= cannot be the ANY address, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        /* Reject address classes that do not qualify as proxy targets and that the kernel would
         * reject: multicast for both families, plus the IPv4 limited broadcast 255.255.255.255. */
        if (in_addr_is_multicast(a.family, &a.address) > 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= cannot be a multicast address, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (a.family == AF_INET && a.address.in.s_addr == htobe32(INADDR_BROADCAST)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= cannot be the limited broadcast address, ignoring: %s",
                           lvalue, rvalue);
                return 0;
        }

        struct in_addr_data *copied = newdup(struct in_addr_data, &a, 1);
        if (!copied)
                return log_oom();

        r = set_ensure_consume(neighbor_proxy_addresses, &in_addr_data_hash_ops_free, copied);
        if (r < 0)
                return log_oom();

        return 0;
}
