/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "in-addr-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor-proxy.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"

static const char* af_to_proxy_setting(int family) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        return family == AF_INET ? "IPv4ProxyARPAddress=" : "IPv6ProxyNDPAddress=";
}

static const char* af_to_proxy_sysctl_setting(int family) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        return family == AF_INET ? "IPv4ProxyARP=" : "IPv6ProxyNDP=";
}

static int neighbor_proxy_family_enabled(const Network *network, int family) {
        assert(network);
        assert(IN_SET(family, AF_INET, AF_INET6));

        return family == AF_INET ? network->proxy_arp : network->ipv6_proxy_ndp;
}

bool network_has_neighbor_proxy_address(const Network *network, int family) {
        struct in_addr_data *a;

        assert(network);
        assert(IN_SET(family, AF_INET, AF_INET6));

        SET_FOREACH(a, network->neighbor_proxy_addresses)
                if (a->family == family)
                        return true;

        return false;
}

static void network_drop_neighbor_proxy_addresses(Network *network, int family) {
        struct in_addr_data *a;

        assert(network);

        /* Build a list of matching keys first, then remove them, to avoid mutating the set during
         * iteration. */
        _cleanup_free_ struct in_addr_data **to_remove = NULL;
        size_t n = 0;

        SET_FOREACH(a, network->neighbor_proxy_addresses)
                if (a->family == family) {
                        if (!GREEDY_REALLOC(to_remove, n + 1))
                                /* On OOM during cleanup, leave the set as-is rather than risking
                                 * a partial mutation; the kernel will simply reject these entries
                                 * later if applicable. */
                                return;
                        to_remove[n++] = a;
                }

        FOREACH_ARRAY(p, to_remove, n)
                free(set_remove(network->neighbor_proxy_addresses, *p));
}

void network_adjust_neighbor_proxy(Network *network) {
        assert(network);

        if (set_isempty(network->neighbor_proxy_addresses))
                return;

        /* If IPv6 is not supported by the kernel, drop any IPv6 entries up front. */
        if (!socket_ipv6_is_supported() &&
            network_has_neighbor_proxy_address(network, AF_INET6)) {
                log_once(LOG_WARNING,
                         "%s: IPv6 proxy NDP addresses are set, but IPv6 is not supported by kernel, "
                         "ignoring IPv6 proxy NDP addresses.", network->filename);
                network_drop_neighbor_proxy_addresses(network, AF_INET6);
        }

        /* Drop per-family entries when the corresponding proxy sysctl was explicitly disabled.
         * For IPv6 the proxy_ndp sysctl is required for manual entries to take effect; for IPv4 we
         * apply the same rule for consistency so that an explicit IPv4ProxyARP=no is respected. */
        int family;
        FOREACH_ARGUMENT(family, AF_INET, AF_INET6)
                if (neighbor_proxy_family_enabled(network, family) == 0 &&
                    network_has_neighbor_proxy_address(network, family)) {
                        log_warning("%s: %s is disabled. Ignoring %s.",
                                    network->filename,
                                    af_to_proxy_sysctl_setting(family),
                                    af_to_proxy_setting(family));
                        network_drop_neighbor_proxy_addresses(network, family);
                }

        if (set_isempty(network->neighbor_proxy_addresses))
                network->neighbor_proxy_addresses = set_free(network->neighbor_proxy_addresses);
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
        assert(address);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r,
                                               address->family == AF_INET ?
                                               "Could not add IPv4 proxy ARP address entry, ignoring" :
                                               "Could not add IPv6 proxy NDP address entry, ignoring");

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

        if (address->family == AF_INET)
                r = sd_netlink_message_append_in_addr(m, NDA_DST, &address->address.in);
        else
                r = sd_netlink_message_append_in6_addr(m, NDA_DST, &address->address.in6);
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
                return log_link_warning_errno(link, r,
                                              address->family == AF_INET ?
                                              "Failed to configure IPv4 proxy ARP address: %m" :
                                              "Failed to configure IPv6 proxy NDP address: %m");

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

static int config_parse_neighbor_proxy_address(
                int family,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue,
                const char *rvalue,
                Network *network) {

        _cleanup_free_ struct in_addr_data *address = NULL;
        union in_addr_union buffer;
        int r;

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(network);

        if (isempty(rvalue)) {
                /* Drop only entries belonging to this family, so that
                 * IPv4ProxyARPAddress= and IPv6ProxyNDPAddress= can be reset independently. */
                network_drop_neighbor_proxy_addresses(network, family);
                if (set_isempty(network->neighbor_proxy_addresses))
                        network->neighbor_proxy_addresses = set_free(network->neighbor_proxy_addresses);
                return 0;
        }

        r = in_addr_from_string(family, rvalue, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (in_addr_is_null(family, &buffer)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s cannot be the ANY address, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (family == AF_INET) {
                /* Reject IPv4 address classes that do not qualify as proxy ARP targets and that
                 * the kernel would reject: multicast (224.0.0.0/4) and the limited broadcast
                 * address 255.255.255.255. */
                if (in4_addr_is_multicast(&buffer.in)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "%s cannot be a multicast address, ignoring: %s", lvalue, rvalue);
                        return 0;
                }

                if (buffer.in.s_addr == htobe32(INADDR_BROADCAST)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "%s cannot be the limited broadcast address, ignoring: %s",
                                   lvalue, rvalue);
                        return 0;
                }
        }

        address = new(struct in_addr_data, 1);
        if (!address)
                return log_oom();

        *address = (struct in_addr_data) {
                .family = family,
                .address = buffer,
        };

        r = set_ensure_consume(&network->neighbor_proxy_addresses, &in_addr_data_hash_ops_free, TAKE_PTR(address));
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_ipv4_proxy_arp_address(
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

        return config_parse_neighbor_proxy_address(AF_INET, unit, filename, line, lvalue, rvalue,
                                                   ASSERT_PTR(userdata));
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

        return config_parse_neighbor_proxy_address(AF_INET6, unit, filename, line, lvalue, rvalue,
                                                   ASSERT_PTR(userdata));
}
