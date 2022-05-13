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

int link_get_local_address(
                Link *link,
                NetDevLocalAddressType type,
                int family,
                int *ret_family,
                union in_addr_union *ret_address) {

        Address *a;

        assert(link);

        switch (type) {
        case NETDEV_LOCAL_ADDRESS_IPV4LL:
                assert(IN_SET(family, AF_UNSPEC, AF_INET));
                family = AF_INET;
                break;
        case NETDEV_LOCAL_ADDRESS_IPV6LL:
                assert(IN_SET(family, AF_UNSPEC, AF_INET6));
                family = AF_INET6;
                break;
        case NETDEV_LOCAL_ADDRESS_DHCP4:
                assert(IN_SET(family, AF_UNSPEC, AF_INET));
                family = AF_INET;
                break;
        case NETDEV_LOCAL_ADDRESS_DHCP6:
                assert(IN_SET(family, AF_UNSPEC, AF_INET6));
                family = AF_INET6;
                break;
        case NETDEV_LOCAL_ADDRESS_SLAAC:
                assert(IN_SET(family, AF_UNSPEC, AF_INET6));
                family = AF_INET6;
                break;
        default:
                assert_not_reached();
        }

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return -EBUSY;

        SET_FOREACH(a, link->addresses) {
                if (!address_is_ready(a))
                        continue;

                if (a->family != family)
                        continue;

                if (in_addr_is_set(a->family, &a->in_addr_peer))
                        continue;

                switch (type) {
                case NETDEV_LOCAL_ADDRESS_IPV4LL:
                        if (a->source != NETWORK_CONFIG_SOURCE_IPV4LL)
                                continue;
                        break;
                case NETDEV_LOCAL_ADDRESS_IPV6LL:
                        if (!in6_addr_is_link_local(&a->in_addr.in6))
                                continue;
                        break;
                case NETDEV_LOCAL_ADDRESS_DHCP4:
                        if (a->source != NETWORK_CONFIG_SOURCE_DHCP4)
                                continue;
                        break;
                case NETDEV_LOCAL_ADDRESS_DHCP6:
                        if (a->source != NETWORK_CONFIG_SOURCE_DHCP6)
                                continue;
                        break;
                case NETDEV_LOCAL_ADDRESS_SLAAC:
                        if (a->source != NETWORK_CONFIG_SOURCE_NDISC)
                                continue;
                        break;
                default:
                        assert_not_reached();
                }

                if (ret_family)
                        *ret_family = a->family;
                if (ret_address)
                        *ret_address = a->in_addr;
                return 1;
        }

        return -ENXIO;
}
