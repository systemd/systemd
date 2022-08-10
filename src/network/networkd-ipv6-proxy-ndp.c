/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>

#include "netlink-util.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "socket-util.h"
#include "string-util.h"

void network_adjust_ipv6_proxy_ndp(Network *network) {
        assert(network);

        if (set_isempty(network->ipv6_proxy_ndp_addresses))
                return;

        if (!socket_ipv6_is_supported()) {
                log_once(LOG_WARNING,
                         "%s: IPv6 proxy NDP addresses are set, but IPv6 is not supported by kernel, "
                         "Ignoring IPv6 proxy NDP addresses.", network->filename);
                network->ipv6_proxy_ndp_addresses = set_free_free(network->ipv6_proxy_ndp_addresses);
        }
}

static int ipv6_proxy_ndp_address_configure_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                struct in6_addr *address) {

        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not add IPv6 proxy ndp address entry, ignoring");

        if (link->static_ipv6_proxy_ndp_messages == 0) {
                log_link_debug(link, "IPv6 proxy NDP addresses set.");
                link->static_ipv6_proxy_ndp_configured = true;
                link_check_ready(link);
        }

        return 1;
}

/* send a request to the kernel to add an IPv6 Proxy entry to the neighbour table */
static int ipv6_proxy_ndp_address_configure(const struct in6_addr *address, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(address);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        /* create new netlink message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH, link->ifindex, AF_INET6);
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_flags(m, NTF_PROXY);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(m, NDA_DST, address);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int ipv6_proxy_ndp_address_process_request(Request *req, Link *link, struct in6_addr *address) {
        int r;

        assert(req);
        assert(link);
        assert(address);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = ipv6_proxy_ndp_address_configure(address, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure IPv6 proxy NDP address: %m");

        return 1;
}

int link_request_static_ipv6_proxy_ndp_addresses(Link *link) {
        struct in6_addr *address;
        int r;

        assert(link);
        assert(link->network);

        link->static_ipv6_proxy_ndp_configured = false;

        SET_FOREACH(address, link->network->ipv6_proxy_ndp_addresses) {
                r = link_queue_request_safe(link, REQUEST_TYPE_IPV6_PROXY_NDP,
                                            address, NULL,
                                            in6_addr_hash_func,
                                            in6_addr_compare_func,
                                            ipv6_proxy_ndp_address_process_request,
                                            &link->static_ipv6_proxy_ndp_messages,
                                            ipv6_proxy_ndp_address_configure_handler,
                                            NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to request IPv6 proxy NDP address: %m");
        }

        if (link->static_ipv6_proxy_ndp_messages == 0) {
                link->static_ipv6_proxy_ndp_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting IPv6 proxy NDP addresses.");
                link_set_state(link, LINK_STATE_CONFIGURING);
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
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union buffer;
        int r;

        assert(filename);
        assert(rvalue);

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
