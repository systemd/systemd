/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netdev-util.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "string-table.h"

static const char * const netdev_local_address_type_table[_NETDEV_LOCAL_ADDRESS_TYPE_MAX] = {
        [NETDEV_LOCAL_ADDRESS_IPV4LL]  = "ipv4_link_local",
        [NETDEV_LOCAL_ADDRESS_IPV6LL]  = "ipv6_link_local",
        [NETDEV_LOCAL_ADDRESS_DHCP4]   = "dhcp4",
        [NETDEV_LOCAL_ADDRESS_DHCP6]   = "dhcp6",
        [NETDEV_LOCAL_ADDRESS_SLAAC]   = "slaac",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_local_address_type, NetDevLocalAddressType);

int link_get_local_address(Link *link, NetDevLocalAddressType type, int family, union in_addr_union *ret) {
        NetworkConfigSource source;
        Address *a;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));

        switch (type) {
        case NETDEV_LOCAL_ADDRESS_IPV4LL:
                assert(family == AF_INET);
                source = NETWORK_CONFIG_SOURCE_IPV4LL;
                break;
        case NETDEV_LOCAL_ADDRESS_IPV6LL:
                assert(family == AF_INET6);
                source = NETWORK_CONFIG_SOURCE_FOREIGN;
                break;
        case NETDEV_LOCAL_ADDRESS_DHCP4:
                assert(family == AF_INET);
                source = NETWORK_CONFIG_SOURCE_DHCP4;
                break;
        case NETDEV_LOCAL_ADDRESS_DHCP6:
                assert(family == AF_INET6);
                source = NETWORK_CONFIG_SOURCE_DHCP6;
                break;
        case NETDEV_LOCAL_ADDRESS_SLAAC:
                assert(family == AF_INET6);
                source = NETWORK_CONFIG_SOURCE_NDISC;
                break;
        default:
                assert_not_reached();
        }

        SET_FOREACH(a, link->addresses) {
                if (a->source != source)
                        continue;

                if (!address_exists(a))
                        continue;

                if (a->family != family)
                        continue;

                if (in_addr_is_set(a->family, &a->in_addr_peer))
                        continue;

                if (source == NETWORK_CONFIG_SOURCE_FOREIGN) {
                        if (a->family != AF_INET6)
                                continue;

                        if (!in6_addr_is_link_local(&a->in_addr.in6))
                                continue;
                }

                if (ret)
                        *ret = a->in_addr;
                return 1;
        }

        return -ENOENT;
}
