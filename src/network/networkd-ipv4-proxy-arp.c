/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-netlink.h"

#include "in-addr-util.h"
#include "networkd-ipv4-proxy-arp.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "set.h"
#include "string-util.h"

static int ipv4_proxy_arp_address_configure_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                struct in_addr *address) {

        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not add IPv4 proxy ARP address entry, ignoring");

        if (link->static_ipv4_proxy_arp_messages == 0) {
                log_link_debug(link, "IPv4 proxy ARP addresses set.");
                link->static_ipv4_proxy_arp_configured = true;
                link_check_ready(link);
        }

        return 1;
}

/* send a request to the kernel to add an IPv4 Proxy entry to the neighbour table */
static int ipv4_proxy_arp_address_configure(const struct in_addr *address, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(address);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        /* create new netlink message */
        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &m, RTM_NEWNEIGH, link->ifindex, AF_INET);
        if (r < 0)
                return r;

        r = sd_rtnl_message_neigh_set_flags(m, NTF_PROXY);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(m, NDA_DST, address);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int ipv4_proxy_arp_address_process_request(Request *req, Link *link, struct in_addr *address) {
        int r;

        assert(req);
        assert(link);
        assert(address);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = ipv4_proxy_arp_address_configure(address, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure IPv4 proxy ARP address: %m");

        return 1;
}

int link_request_static_ipv4_proxy_arp_addresses(Link *link) {
        struct in_addr *address;
        int r;

        assert(link);
        assert(link->network);

        link->static_ipv4_proxy_arp_configured = false;

        SET_FOREACH(address, link->network->ipv4_proxy_arp_addresses) {
                r = link_queue_request_safe(link, REQUEST_TYPE_IPV4_PROXY_ARP,
                                            address, NULL,
                                            in4_addr_hash_func,
                                            in4_addr_compare_func,
                                            ipv4_proxy_arp_address_process_request,
                                            &link->static_ipv4_proxy_arp_messages,
                                            ipv4_proxy_arp_address_configure_handler,
                                            NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to request IPv4 proxy ARP address: %m");
        }

        if (link->static_ipv4_proxy_arp_messages == 0) {
                link->static_ipv4_proxy_arp_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting IPv4 proxy ARP addresses.");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

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

        _cleanup_free_ struct in_addr *address = NULL;
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union buffer;
        int r;

        assert(filename);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->ipv4_proxy_arp_addresses = set_free(network->ipv4_proxy_arp_addresses);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse IPv4 proxy ARP address, ignoring: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(AF_INET, &buffer)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "IPv4 proxy ARP address cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        address = newdup(struct in_addr, &buffer.in, 1);
        if (!address)
                return log_oom();

        r = set_ensure_consume(&network->ipv4_proxy_arp_addresses, &in4_addr_hash_ops_free, TAKE_PTR(address));
        if (r < 0)
                return log_oom();

        return 0;
}
