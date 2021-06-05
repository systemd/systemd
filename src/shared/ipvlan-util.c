/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "ipvlan-util.h"
#include "string-table.h"

static const char* const ipvlan_mode_table[_NETDEV_IPVLAN_MODE_MAX] = {
        [NETDEV_IPVLAN_MODE_L2] = "L2",
        [NETDEV_IPVLAN_MODE_L3] = "L3",
        [NETDEV_IPVLAN_MODE_L3S] = "L3S",
};

DEFINE_STRING_TABLE_LOOKUP(ipvlan_mode, IPVlanMode);

static const char* const ipvlan_flags_table[_NETDEV_IPVLAN_FLAGS_MAX] = {
        [NETDEV_IPVLAN_FLAGS_BRIGDE] = "bridge",
        [NETDEV_IPVLAN_FLAGS_PRIVATE] = "private",
        [NETDEV_IPVLAN_FLAGS_VEPA] = "vepa",
};

DEFINE_STRING_TABLE_LOOKUP(ipvlan_flags, IPVlanFlags);
