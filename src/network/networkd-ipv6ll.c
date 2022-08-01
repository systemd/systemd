/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <linux/if_arp.h>

#include "in-addr-util.h"
#include "networkd-address.h"
#include "networkd-ipv6ll.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "sysctl-util.h"

bool link_ipv6ll_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (!link->network)
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (STRPTR_IN_SET(link->kind, "vrf", "wireguard", "ipip", "gre", "sit", "vti", "nlmon"))
                return false;

        if (link->network->bond)
                return false;

        return link->network->link_local & ADDRESS_FAMILY_IPV6;
}

bool link_may_have_ipv6ll(Link *link, bool check_multicast) {
        assert(link);

        /*
         * This is equivalent to link_ipv6ll_enabled() for non-WireGuard interfaces.
         *
         * For WireGuard interface, the kernel does not assign any IPv6LL addresses, but we can assign
         * it manually. It is necessary to set an IPv6LL address manually to run NDisc or RADV on
         * WireGuard interface. Note, also Multicast=yes must be set. See #17380.
         *
         * TODO: May be better to introduce GenerateIPv6LinkLocalAddress= setting, and use algorithms
         *       used in networkd-address-generation.c
         */

        if (link_ipv6ll_enabled(link))
                return true;

        /* IPv6LL address can be manually assigned on WireGuard interface. */
        if (streq_ptr(link->kind, "wireguard")) {
                Address *a;

                if (!link->network)
                        return false;

                if (check_multicast && !FLAGS_SET(link->flags, IFF_MULTICAST) && link->network->multicast <= 0)
                        return false;

                ORDERED_HASHMAP_FOREACH(a, link->network->addresses_by_section) {
                        if (a->family != AF_INET6)
                                continue;
                        if (in6_addr_is_set(&a->in_addr_peer.in6))
                                continue;
                        if (in6_addr_is_link_local(&a->in_addr.in6))
                                return true;
                }
        }

        return false;
}

IPv6LinkLocalAddressGenMode link_get_ipv6ll_addrgen_mode(Link *link) {
        assert(link);

        if (!link_ipv6ll_enabled(link))
                return IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE;

        if (link->network->ipv6ll_address_gen_mode >= 0)
                return link->network->ipv6ll_address_gen_mode;

        if (in6_addr_is_set(&link->network->ipv6ll_stable_secret))
                return IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY;

        return IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64;
}

int ipv6ll_addrgen_mode_fill_message(sd_netlink_message *message, IPv6LinkLocalAddressGenMode mode) {
        int r;

        assert(message);
        assert(mode >= 0 && mode < _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX);

        r = sd_netlink_message_open_container(message, IFLA_AF_SPEC);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(message, AF_INET6);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(message, IFLA_INET6_ADDR_GEN_MODE, mode);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return r;

        return 0;
}

int link_update_ipv6ll_addrgen_mode(Link *link, sd_netlink_message *message) {
        uint8_t mode;
        int family, r;

        assert(link);
        assert(message);

        r = sd_rtnl_message_get_family(message, &family);
        if (r < 0)
                return r;

        if (family != AF_UNSPEC)
                return 0;

        r = sd_netlink_message_enter_container(message, IFLA_AF_SPEC);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = sd_netlink_message_enter_container(message, AF_INET6);
        if (r == -ENODATA)
                return sd_netlink_message_exit_container(message);
        if (r < 0)
                return r;

        mode = (uint8_t) link->ipv6ll_address_gen_mode;
        r = sd_netlink_message_read_u8(message, IFLA_INET6_ADDR_GEN_MODE, &mode);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_netlink_message_exit_container(message);
        if (r < 0)
                return r;

        r = sd_netlink_message_exit_container(message);
        if (r < 0)
                return r;

        if (mode == (uint8_t) link->ipv6ll_address_gen_mode)
                return 0;

        if (mode >= _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX) {
                log_link_debug(link, "Received invalid IPv6 link-local address generation mode (%u), ignoring.", mode);
                return 0;
        }

        if (link->ipv6ll_address_gen_mode < 0)
                log_link_debug(link, "Saved IPv6 link-local address generation mode: %s",
                               ipv6_link_local_address_gen_mode_to_string(mode));
        else
                log_link_debug(link, "IPv6 link-local address generation mode is changed: %s -> %s",
                               ipv6_link_local_address_gen_mode_to_string(link->ipv6ll_address_gen_mode),
                               ipv6_link_local_address_gen_mode_to_string(mode));

        link->ipv6ll_address_gen_mode = mode;
        return 0;
}

#define STABLE_SECRET_APP_ID_1 SD_ID128_MAKE(aa,05,1d,94,43,68,45,07,b9,73,f1,e8,e4,b7,34,52)
#define STABLE_SECRET_APP_ID_2 SD_ID128_MAKE(52,c4,40,a0,9f,2f,48,58,a9,3a,f6,29,25,ba,7a,7d)

int link_set_ipv6ll_stable_secret(Link *link) {
        struct in6_addr a;
        int r;

        assert(link);
        assert(link->network);

        if (link->network->ipv6ll_address_gen_mode != IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY)
                return 0;

        if (in6_addr_is_set(&link->network->ipv6ll_stable_secret))
                a = link->network->ipv6ll_stable_secret;
        else {
                sd_id128_t key;
                le64_t v;

                /* Generate a stable secret address from machine-ID and the interface name. */

                r = sd_id128_get_machine_app_specific(STABLE_SECRET_APP_ID_1, &key);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to generate key: %m");

                v = htole64(siphash24_string(link->ifname, key.bytes));
                memcpy(a.s6_addr, &v, sizeof(v));

                r = sd_id128_get_machine_app_specific(STABLE_SECRET_APP_ID_2, &key);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to generate key: %m");

                v = htole64(siphash24_string(link->ifname, key.bytes));
                assert_cc(sizeof(v) * 2 == sizeof(a.s6_addr));
                memcpy(a.s6_addr + sizeof(v), &v, sizeof(v));
        }

        return sysctl_write_ip_property(AF_INET6, link->ifname, "stable_secret",
                                        IN6_ADDR_TO_STRING(&a));
}

int link_set_ipv6ll_addrgen_mode(Link *link, IPv6LinkLocalAddressGenMode mode) {
        assert(link);
        assert(mode >= 0 && mode < _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX);

        if (mode == link->ipv6ll_address_gen_mode)
                return 0;

        return sysctl_write_ip_property_uint32(AF_INET6, link->ifname, "addr_gen_mode", mode);
}

static const char* const ipv6_link_local_address_gen_mode_table[_IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX] = {
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64]          = "eui64",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE]           = "none",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY] = "stable-privacy",
        [IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM]         = "random",
};

DEFINE_STRING_TABLE_LOOKUP(ipv6_link_local_address_gen_mode, IPv6LinkLocalAddressGenMode);
DEFINE_CONFIG_PARSE_ENUM(
        config_parse_ipv6_link_local_address_gen_mode,
        ipv6_link_local_address_gen_mode,
        IPv6LinkLocalAddressGenMode,
        "Failed to parse IPv6 link-local address generation mode");
