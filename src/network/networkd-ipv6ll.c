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

bool link_may_have_ipv6ll(Link *link) {
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
        "Failed to parse IPv6 link local address generation mode");
