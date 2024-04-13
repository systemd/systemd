/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "af-list.h"
#include "missing_network.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-sysctl.h"
#include "socket-util.h"
#include "string-table.h"
#include "sysctl-util.h"

static void hold_forwarding_fds(Manager *manager) {
        manager->sysctl_fd.ip_default_forwarding[0] = sysctl_hold_fd("net/ipv4/conf/default/forwarding");
        manager->sysctl_fd.ip_default_forwarding[1] = sysctl_hold_fd("net/ipv4/conf/all/forwarding");
        manager->sysctl_fd.ip_all_forwarding[0] = sysctl_hold_fd("net/ipv6/conf/default/forwarding");
        manager->sysctl_fd.ip_all_forwarding[1] = sysctl_hold_fd("net/ipv6/conf/all/forwarding");
}

static bool hold_link_fds(Link *link) {
        char knob[PATH_MAX];

#define SYSCTL_HOLD_FD(name, ipv) \
        snprintf(knob, PATH_MAX, "net/ipv" #ipv "/conf/%s/" #name, link->ifname); \
        link->sysctl_fd.name = sysctl_hold_fd(knob);
#define SYSCTL_HOLD_FD_DUAL(name) \
        snprintf(knob, PATH_MAX, "net/ipv4/conf/%s/" #name, link->ifname); \
        link->sysctl_fd.name[0] = sysctl_hold_fd(knob);                    \
        snprintf(knob, PATH_MAX, "net/ipv6/conf/%s/" #name, link->ifname); \
        link->sysctl_fd.name[1] = sysctl_hold_fd(knob);

        SYSCTL_HOLD_FD(disable_ipv6, 6);
        SYSCTL_HOLD_FD(proxy_arp, 4);
        SYSCTL_HOLD_FD(proxy_arp_pvlan, 4);
        SYSCTL_HOLD_FD_DUAL(forwarding);
        SYSCTL_HOLD_FD(rp_filter, 4);
        SYSCTL_HOLD_FD(use_tempaddr, 6);
        SYSCTL_HOLD_FD(accept_ra, 6);
        SYSCTL_HOLD_FD(dad_transmits, 6);
        SYSCTL_HOLD_FD(hop_limit, 6);
        SYSCTL_HOLD_FD(retrans_time_ms, 6);
        SYSCTL_HOLD_FD(proxy_ndp, 6);
        SYSCTL_HOLD_FD(mtu, 6);
        SYSCTL_HOLD_FD(accept_local, 4);
        SYSCTL_HOLD_FD(route_localnet, 4);
        SYSCTL_HOLD_FD(promote_secondaries, 4);

#undef SYSCTL_HOLD_FD_DUAL
#undef SYSCTL_HOLD_FD

        return false;
}

static int try_write(int fd, const char *value, size_t size) {
        if (fd < 0)
                return fd;

        return pwrite(fd, value, size, 0);
}

static int try_write_int(int fd, int value) {
        char buf[DECIMAL_STR_MAX(int)];

        xsprintf(buf, "%i", value);

        return try_write(fd, buf, strlen(buf));
}

static int try_write_uint32(int fd, uint32_t value) {
        char buf[DECIMAL_STR_MAX(uint32_t)];

        xsprintf(buf, "%" PRIu32, value);

        return try_write(fd, buf, strlen(buf));
}

static void manager_set_ip_forwarding(Manager *manager, int family) {
        int r, t;

        assert(manager);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return;

        t = manager->ip_forwarding[family == AF_INET6];
        if (t < 0)
                return; /* keep */

        hold_forwarding_fds(manager);

        /* First, set the default value. */
        r = try_write(manager->sysctl_fd.ip_default_forwarding[family == AF_INET6], one_zero(t), 1);
        if (r < 0)
                log_warning_errno(r, "Failed to %s the default %s forwarding: %m",
                                  enable_disable(t), af_to_ipv4_ipv6(family));

        /* Then, set the value to all interfaces. */
        r = try_write(manager->sysctl_fd.ip_all_forwarding[family == AF_INET6], one_zero(t), 1);
        if (r < 0)
                log_warning_errno(r, "Failed to %s %s forwarding for all interfaces: %m",
                                  enable_disable(t), af_to_ipv4_ipv6(family));
}

void manager_set_sysctl(Manager *manager) {
        assert(manager);
        assert(!manager->test_mode);

        manager_set_ip_forwarding(manager, AF_INET);
        manager_set_ip_forwarding(manager, AF_INET6);
}

static bool link_is_configured_for_family(Link *link, int family) {
        assert(link);

        if (!link->network)
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        /* CAN devices do not support IP layer. Most of the functions below are never called for CAN devices,
         * but link_set_ipv6_mtu() may be called after setting interface MTU, and warn about the failure. For
         * safety, let's unconditionally check if the interface is not a CAN device. */
        if (IN_SET(family, AF_INET, AF_INET6) && link->iftype == ARPHRD_CAN)
                return false;

        if (family == AF_INET6 && !socket_ipv6_is_supported())
                return false;

        return true;
}

static int link_update_ipv6_sysctl(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (!link_ipv6_enabled(link))
                return 0;

        return try_write(link->sysctl_fd.disable_ipv6, "0", 1);
}

static int link_set_proxy_arp(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->proxy_arp < 0)
                return 0;

        return try_write(link->sysctl_fd.proxy_arp, one_zero(link->network->proxy_arp > 0), 1);
}

static int link_set_proxy_arp_pvlan(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->proxy_arp_pvlan < 0)
                return 0;

        return try_write(link->sysctl_fd.proxy_arp_pvlan, one_zero(link->network->proxy_arp_pvlan > 0), 1);
}

int link_get_ip_forwarding(Link *link, int family) {
        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* If it is explicitly specified, then honor the setting. */
        int t = link->network->ip_forwarding[family == AF_INET6];
        if (t >= 0)
                return t;

        /* If IPMasquerade= is enabled, also enable IP forwarding. */
        if (family == AF_INET && FLAGS_SET(link->network->ip_masquerade, ADDRESS_FAMILY_IPV4))
                return true;
        if (family == AF_INET6 && FLAGS_SET(link->network->ip_masquerade, ADDRESS_FAMILY_IPV6))
                return true;

        /* If IPv6SendRA= is enabled, also enable IPv6 forwarding. */
        if (family == AF_INET6 && link_radv_enabled(link))
                return true;

        /* Otherwise, use the global setting. */
        return link->manager->ip_forwarding[family == AF_INET6];
}

static int link_set_ip_forwarding(Link *link, int family) {
        int r, t;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (!link_is_configured_for_family(link, family))
                return 0;

        t = link_get_ip_forwarding(link, family);
        if (t < 0)
                return 0; /* keep */

        r = try_write(link->sysctl_fd.forwarding[family == AF_INET6], one_zero(t), 1);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to %s %s forwarding, ignoring: %m",
                                              enable_disable(t), af_to_ipv4_ipv6(family));

        return 0;
}

static int link_set_ipv4_rp_filter(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_rp_filter < 0)
                return 0;

        return try_write_int(link->sysctl_fd.rp_filter, link->network->ipv4_rp_filter);
}

static int link_set_ipv6_privacy_extensions(Link *link) {
        IPv6PrivacyExtensions val;

        assert(link);
        assert(link->manager);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        val = link->network->ipv6_privacy_extensions;
        if (val < 0) /* If not specified, then use the global setting. */
                val = link->manager->ipv6_privacy_extensions;

        /* When "kernel", do not update the setting. */
        if (val == IPV6_PRIVACY_EXTENSIONS_KERNEL)
                return 0;

        return try_write_int(link->sysctl_fd.use_tempaddr, (int) val);
}

static int link_set_ipv6_accept_ra(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        return try_write(link->sysctl_fd.accept_ra, "0", 1);
}

static int link_set_ipv6_dad_transmits(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_dad_transmits < 0)
                return 0;

        return try_write_int(link->sysctl_fd.dad_transmits, link->network->ipv6_dad_transmits);
}

static int link_set_ipv6_hop_limit(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_hop_limit <= 0)
                return 0;

        return try_write_int(link->sysctl_fd.hop_limit, link->network->ipv6_hop_limit);
}

static int link_set_ipv6_retransmission_time(Link *link) {
        usec_t retrans_time_ms;

        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (!timestamp_is_set(link->network->ipv6_retransmission_time))
                return 0;

        retrans_time_ms = DIV_ROUND_UP(link->network->ipv6_retransmission_time, USEC_PER_MSEC);
         if (retrans_time_ms <= 0 || retrans_time_ms > UINT32_MAX)
                return 0;

        // return try_write_uint32(link->sysctl_fd.retrans_time_ms, retrans_time_ms);
        return sysctl_write_ip_neighbor_property_uint32(AF_INET6, link->ifname, "retrans_time_ms", retrans_time_ms);
}

static int link_set_ipv6_proxy_ndp(Link *link) {
        bool v;

        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        if (link->network->ipv6_proxy_ndp >= 0)
                v = link->network->ipv6_proxy_ndp;
        else
                v = !set_isempty(link->network->ipv6_proxy_ndp_addresses);

        return try_write(link->sysctl_fd.proxy_ndp, one_zero(v), 1);
}

int link_set_ipv6_mtu(Link *link, int log_level) {
        uint32_t mtu = 0;

        assert(link);

        if (!link_is_configured_for_family(link, AF_INET6))
                return 0;

        assert(link->network);

        if (link->network->ndisc_use_mtu)
                mtu = link->ndisc_mtu;
        if (mtu == 0)
                mtu = link->network->ipv6_mtu;
        if (mtu == 0)
                return 0;

        if (mtu > link->mtu) {
                log_link_full(link, log_level,
                              "Reducing requested IPv6 MTU %"PRIu32" to the interface's maximum MTU %"PRIu32".",
                              mtu, link->mtu);
                mtu = link->mtu;
        }

        return try_write_uint32(link->sysctl_fd.mtu, mtu);
}

static int link_set_ipv4_accept_local(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_accept_local < 0)
                return 0;

        return try_write(link->sysctl_fd.accept_local, one_zero(link->network->ipv4_accept_local > 0), 1);
}

static int link_set_ipv4_route_localnet(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        if (link->network->ipv4_route_localnet < 0)
                return 0;

        return try_write(link->sysctl_fd.route_localnet, one_zero(link->network->ipv4_route_localnet > 0), 1);
}

static int link_set_ipv4_promote_secondaries(Link *link) {
        assert(link);

        if (!link_is_configured_for_family(link, AF_INET))
                return 0;

        /* If promote_secondaries is not set, DHCP will work only as long as the IP address does not
         * changes between leases. The kernel will remove all secondary IP addresses of an interface
         * otherwise. The way systemd-networkd works is that the new IP of a lease is added as a
         * secondary IP and when the primary one expires it relies on the kernel to promote the
         * secondary IP. See also https://github.com/systemd/systemd/issues/7163 */
        return try_write(link->sysctl_fd.promote_secondaries, "1", 1);
}

int link_set_sysctl(Link *link) {
        int r;

        assert(link);

        hold_link_fds(link);

        /* If IPv6 configured that is static IPv6 address and IPv6LL autoconfiguration is enabled
         * for this interface, then enable IPv6 */
        r = link_update_ipv6_sysctl(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable IPv6, ignoring: %m");

        r = link_set_proxy_arp(link);
        if (r < 0)
               log_link_warning_errno(link, r, "Cannot configure proxy ARP for interface, ignoring: %m");

        r = link_set_proxy_arp_pvlan(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot configure proxy ARP private VLAN for interface, ignoring: %m");

        (void) link_set_ip_forwarding(link, AF_INET);
        (void) link_set_ip_forwarding(link, AF_INET6);

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

        r = link_set_ipv6_retransmission_time(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 retransmission time for interface, ignoring: %m");

        r = link_set_ipv6_proxy_ndp(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 proxy NDP, ignoring: %m");

        r = link_set_ipv6_mtu(link, LOG_INFO);
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

        r = link_set_ipv4_rp_filter(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv4 reverse path filtering for interface, ignoring: %m");

        r = link_set_ipv4_promote_secondaries(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot enable promote_secondaries for interface, ignoring: %m");

        return 0;
}

static const char* const ipv6_privacy_extensions_table[_IPV6_PRIVACY_EXTENSIONS_MAX] = {
        [IPV6_PRIVACY_EXTENSIONS_NO]            = "no",
        [IPV6_PRIVACY_EXTENSIONS_PREFER_PUBLIC] = "prefer-public",
        [IPV6_PRIVACY_EXTENSIONS_YES]           = "yes",
        [IPV6_PRIVACY_EXTENSIONS_KERNEL]        = "kernel",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(ipv6_privacy_extensions, IPv6PrivacyExtensions,
                                        IPV6_PRIVACY_EXTENSIONS_YES);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipv6_privacy_extensions, ipv6_privacy_extensions, IPv6PrivacyExtensions,
                         "Failed to parse IPv6 privacy extensions option");

static const char* const ip_reverse_path_filter_table[_IP_REVERSE_PATH_FILTER_MAX] = {
        [IP_REVERSE_PATH_FILTER_NO]     = "no",
        [IP_REVERSE_PATH_FILTER_STRICT] = "strict",
        [IP_REVERSE_PATH_FILTER_LOOSE]  = "loose",
};

DEFINE_STRING_TABLE_LOOKUP(ip_reverse_path_filter, IPReversePathFilter);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ip_reverse_path_filter, ip_reverse_path_filter, IPReversePathFilter,
                         "Failed to parse IP reverse path filter option");

int config_parse_ip_forward_deprecated(
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

        assert(filename);

        log_syntax(unit, LOG_WARNING, filename, line, 0,
                   "IPForward= setting is deprecated. "
                   "Please use IPv4Forwarding= and/or IPv6Forwarding= in networkd.conf for global setting, "
                   "and the same settings in .network files for per-interface setting.");
        return 0;
}
