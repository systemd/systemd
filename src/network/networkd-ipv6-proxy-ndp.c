/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/ether.h>
#include <linux/if.h>
#include <unistd.h>

#include "fileio.h"
#include "netlink-util.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "string-util.h"
#include "socket-util.h"

static bool ipv6_proxy_ndp_is_needed(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->network->ipv6_proxy_ndp >= 0)
                return link->network->ipv6_proxy_ndp;

        if (link->network->n_ipv6_proxy_ndp_addresses == 0)
                return false;

        return true;
}

static int ipv6_proxy_ndp_set(Link *link) {
        const char *p = NULL;
        int r, v;

        assert(link);

        if (!socket_ipv6_is_supported())
                return 0;

        v = ipv6_proxy_ndp_is_needed(link);
        p = strjoina("/proc/sys/net/ipv6/conf/", link->ifname, "/proxy_ndp");

        r = write_string_file(p, one_zero(v), WRITE_STRING_FILE_VERIFY_ON_FAILURE);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure proxy NDP for interface: %m");

        return 0;
}

int ipv6_proxy_ndp_address_new_static(Network *network, IPv6ProxyNDPAddress **ret) {
        _cleanup_(ipv6_proxy_ndp_address_freep) IPv6ProxyNDPAddress *ipv6_proxy_ndp_address = NULL;

        assert(network);
        assert(ret);

        /* allocate space for IPv6ProxyNDPAddress entry */
        ipv6_proxy_ndp_address = new0(IPv6ProxyNDPAddress, 1);
        if (!ipv6_proxy_ndp_address)
                return -ENOMEM;

        ipv6_proxy_ndp_address->network = network;

        LIST_PREPEND(ipv6_proxy_ndp_addresses, network->ipv6_proxy_ndp_addresses, ipv6_proxy_ndp_address);
        network->n_ipv6_proxy_ndp_addresses++;

        *ret = ipv6_proxy_ndp_address;
        ipv6_proxy_ndp_address = NULL;

        return 0;
}

void ipv6_proxy_ndp_address_free(IPv6ProxyNDPAddress *ipv6_proxy_ndp_address) {
        if (!ipv6_proxy_ndp_address)
                return;

        if (ipv6_proxy_ndp_address->network) {
                LIST_REMOVE(ipv6_proxy_ndp_addresses, ipv6_proxy_ndp_address->network->ipv6_proxy_ndp_addresses,
                            ipv6_proxy_ndp_address);

                assert(ipv6_proxy_ndp_address->network->n_ipv6_proxy_ndp_addresses > 0);
                ipv6_proxy_ndp_address->network->n_ipv6_proxy_ndp_addresses--;
        }

        free(ipv6_proxy_ndp_address);
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

        Network *network = userdata;
        _cleanup_(ipv6_proxy_ndp_address_freep) IPv6ProxyNDPAddress *ipv6_proxy_ndp_address = NULL;
        int r;
        union in_addr_union buffer;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = ipv6_proxy_ndp_address_new_static(network, &ipv6_proxy_ndp_address);
        if (r < 0)
                return r;

        r = in_addr_from_string(AF_INET6, rvalue, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse IPv6 proxy NDP address, ignoring: %s",
                           rvalue);
                return 0;
        }

        r = in_addr_is_null(AF_INET6, &buffer);
        if (r != 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "IPv6 proxy NDP address cannot be the ANY address, ignoring: %s", rvalue);
                return 0;
        }

        ipv6_proxy_ndp_address->in_addr = buffer.in6;
        ipv6_proxy_ndp_address = NULL;

        return 0;
}

static int set_ipv6_proxy_ndp_address_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_link_error_errno(link, r, "Could not add IPv6 proxy ndp address entry: %m");

        return 1;
}

/* send a request to the kernel to add a IPv6 Proxy entry to the neighbour table */
int ipv6_proxy_ndp_address_configure(Link *link, IPv6ProxyNDPAddress *ipv6_proxy_ndp_address) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        sd_netlink *rtnl;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(ipv6_proxy_ndp_address);

        rtnl = link->manager->rtnl;

        /* create new netlink message */
        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_NEWNEIGH, link->ifindex, AF_INET6);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_neigh_set_flags(req, NLM_F_REQUEST | NTF_PROXY);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_message_append_in6_addr(req, NDA_DST, &ipv6_proxy_ndp_address->in_addr);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call_async(rtnl, NULL, req, set_ipv6_proxy_ndp_address_handler,
                                  link_netlink_destroy_callback, link, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

/* configure all ipv6 proxy ndp addresses */
int ipv6_proxy_ndp_addresses_configure(Link *link) {
        IPv6ProxyNDPAddress *ipv6_proxy_ndp_address;
        int r;

        assert(link);

        /* enable or disable proxy_ndp itself depending on whether ipv6_proxy_ndp_addresses are set or not */
        r = ipv6_proxy_ndp_set(link);
        if (r != 0)
                return r;

        LIST_FOREACH(ipv6_proxy_ndp_addresses, ipv6_proxy_ndp_address, link->network->ipv6_proxy_ndp_addresses) {
                r = ipv6_proxy_ndp_address_configure(link, ipv6_proxy_ndp_address);
                if (r != 0)
                        return r;
        }
        return 0;
}
