/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "macro.h"

typedef struct Link Link;

typedef enum NetDevLocalAddressType {
        NETDEV_LOCAL_ADDRESS_IPV4LL,
        NETDEV_LOCAL_ADDRESS_IPV6LL,
        NETDEV_LOCAL_ADDRESS_DHCP4,
        NETDEV_LOCAL_ADDRESS_DHCP6,
        NETDEV_LOCAL_ADDRESS_SLAAC,
        _NETDEV_LOCAL_ADDRESS_TYPE_MAX,
        _NETDEV_LOCAL_ADDRESS_TYPE_INVALID = -EINVAL,
} NetDevLocalAddressType;

const char* netdev_local_address_type_to_string(NetDevLocalAddressType t) _const_;
NetDevLocalAddressType netdev_local_address_type_from_string(const char *s) _pure_;

int link_get_local_address(
                Link *link,
                NetDevLocalAddressType type,
                int family,
                int *ret_family,
                union in_addr_union *ret_address);
