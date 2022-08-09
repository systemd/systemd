/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>

#include "missing_network.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-sysctl.h"
#include "socket-util.h"
#include "string-table.h"
#include "sysctl-util.h"

static int link_update_ipv6_sysctl(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link_ipv6_enabled(link))
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "disable_ipv6", false);
}

static int link_set_proxy_arp(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->proxy_arp < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "proxy_arp", link->network->proxy_arp > 0);
}

static bool link_ip_forward_enabled(Link *link, int family) {
        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        return link->network->ip_forward & (family == AF_INET ? ADDRESS_FAMILY_IPV4 : ADDRESS_FAMILY_IPV6);
}

static int link_set_ipv4_forward(Link *link) {
        assert(link);

        if (!link_ip_forward_enabled(link, AF_INET))
                return 0;

        /* We propagate the forwarding flag from one interface to the
         * global setting one way. This means: as long as at least one
         * interface was configured at any time that had IP forwarding
         * enabled the setting will stay on for good. We do this
         * primarily to keep IPv4 and IPv6 packet forwarding behaviour
         * somewhat in sync (see below). */

        return sysctl_write_ip_property(AF_INET, NULL, "ip_forward", "1");
}

static int link_set_ipv6_forward(Link *link) {
        assert(link);

        if (!link_ip_forward_enabled(link, AF_INET6))
                return 0;

        /* On Linux, the IPv6 stack does not know a per-interface
         * packet forwarding setting: either packet forwarding is on
         * for all, or off for all. We hence don't bother with a
         * per-interface setting, but simply propagate the interface
         * flag, if it is set, to the global flag, one-way. Note that
         * while IPv4 would allow a per-interface flag, we expose the
         * same behaviour there and also propagate the setting from
         * one to all, to keep things simple (see above). */

        return sysctl_write_ip_property(AF_INET6, "all", "forwarding", "1");
}

static int link_set_ipv6_privacy_extensions(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        // this is the special "kernel" value
        if (link->network->ipv6_privacy_extensions == _IPV6_PRIVACY_EXTENSIONS_INVALID)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "use_tempaddr", (int) link->network->ipv6_privacy_extensions);
}

static int link_set_ipv6_accept_ra(Link *link) {
        assert(link);

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        return sysctl_write_ip_property(AF_INET6, link->ifname, "accept_ra", "0");
}

static int link_set_ipv6_dad_transmits(Link *link) {
        assert(link);

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_dad_transmits < 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "dad_transmits", link->network->ipv6_dad_transmits);
}

static int link_set_ipv6_hop_limit(Link *link) {
        assert(link);

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_hop_limit < 0)
                return 0;

        return sysctl_write_ip_property_int(AF_INET6, link->ifname, "hop_limit", link->network->ipv6_hop_limit);
}

static int link_set_ipv6_proxy_ndp(Link *link) {
        bool v;

        assert(link);

        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_proxy_ndp >= 0)
                v = link->network->ipv6_proxy_ndp;
        else
                v = !set_isempty(link->network->ipv6_proxy_ndp_addresses);

        return sysctl_write_ip_property_boolean(AF_INET6, link->ifname, "proxy_ndp", v);
}

int link_set_ipv6_mtu(Link *link) {
        uint32_t mtu;

        assert(link);

        /* Make this a NOP if IPv6 is not available */
        if (!socket_ipv6_is_supported())
                return 0;

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ipv6_mtu == 0)
                return 0;

        mtu = link->network->ipv6_mtu;
        if (mtu > link->max_mtu) {
                log_link_warning(link, "Reducing requested IPv6 MTU %"PRIu32" to the interface's maximum MTU %"PRIu32".",
                                 mtu, link->max_mtu);
                mtu = link->max_mtu;
        }

        return sysctl_write_ip_property_uint32(AF_INET6, link->ifname, "mtu", mtu);
}

static int link_set_ipv4_accept_local(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (link->network->ipv4_accept_local < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "accept_local", link->network->ipv4_accept_local > 0);
}

static int link_set_ipv4_route_localnet(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return 0;

        if (link->network->ipv4_route_localnet < 0)
                return 0;

        return sysctl_write_ip_property_boolean(AF_INET, link->ifname, "route_localnet", link->network->ipv4_route_localnet > 0);
}

int link_set_sysctl(Link *link) {
        int r;

        assert(link);

        /* If IPv6 configured that is static IPv6 address and IPv6LL autoconfiguration is enabled
         * for this interface, then enable IPv6 */
        r = link_update_ipv6_sysctl(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable IPv6, ignoring: %m");

        r = link_set_proxy_arp(link);
        if (r < 0)
               log_link_warning_errno(link, r, "Cannot configure proxy ARP for interface, ignoring: %m");

        r = link_set_ipv4_forward(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot turn on IPv4 packet forwarding, ignoring: %m");

        r = link_set_ipv6_forward(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 packet forwarding, ignoring: %m");

        r = link_set_ipv6_privacy_extensions(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure IPv6 privacy extensions for interface, ignoring: %m");

        r = link_set_ipv6_accept_ra(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot disable kernel IPv6 accept_ra for interface, ignoring: %m");

        r = link_set_ipv6_dad_transmits(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 dad transmits for interface, ignoring: %m");

        r = link_set_ipv6_hop_limit(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 hop limit for interface, ignoring: %m");

        r = link_set_ipv6_proxy_ndp(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 proxy NDP, ignoring: %m");

        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 MTU, ignoring: %m");

        r = link_set_ipv6ll_stable_secret(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set stable secret address for IPv6 link-local address: %m");

        r = link_set_ipv4_accept_local(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 accept_local flag for interface, ignoring: %m");

        r = link_set_ipv4_route_localnet(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 route_localnet flag for interface, ignoring: %m");

        /* If promote_secondaries is not set, DHCP will work only as long as the IP address does not
         * changes between leases. The kernel will remove all secondary IP addresses of an interface
         * otherwise. The way systemd-networkd works is that the new IP of a lease is added as a
         * secondary IP and when the primary one expires it relies on the kernel to promote the
         * secondary IP. See also https://github.com/systemd/systemd/issues/7163 */
        r = sysctl_write_ip_property_boolean(AF_INET, link->ifname, "promote_secondaries", true);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable promote_secondaries for interface, ignoring: %m");

        return 0;
}

static const char* const ipv6_privacy_extensions_table[_IPV6_PRIVACY_EXTENSIONS_MAX] = {
        [IPV6_PRIVACY_EXTENSIONS_NO] = "no",
        [IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC] = "prefer-public",
        [IPV6_PRIVACY_EXTENSIONS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(ipv6_privacy_extensions, IPv6PrivacyExtensions,
                                        IPV6_PRIVACY_EXTENSIONS_YES);

int config_parse_ipv6_privacy_extensions(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        IPv6PrivacyExtensions s, *ipv6_privacy_extensions = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        s = ipv6_privacy_extensions_from_string(rvalue);
        if (s < 0) {
                if (streq(rvalue, "kernel"))
                        s = _IPV6_PRIVACY_EXTENSIONS_INVALID;
                else {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Failed to parse IPv6 privacy extensions option, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *ipv6_privacy_extensions = s;

        return 0;
}
