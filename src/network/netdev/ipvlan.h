/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <netinet/in.h>
#include <linux/if_link.h>

#include "netdev/netdev.h"

typedef enum IPVlanMode {
        NETDEV_IPVLAN_MODE_L2 = IPVLAN_MODE_L2,
        NETDEV_IPVLAN_MODE_L3 = IPVLAN_MODE_L3,
        NETDEV_IPVLAN_MODE_L3S = IPVLAN_MODE_L3S,
        _NETDEV_IPVLAN_MODE_MAX,
        _NETDEV_IPVLAN_MODE_INVALID = -1
} IPVlanMode;

typedef enum IPVlanFlags {
        NETDEV_IPVLAN_FLAGS_BRIGDE,
        NETDEV_IPVLAN_FLAGS_PRIVATE = IPVLAN_F_PRIVATE,
        NETDEV_IPVLAN_FLAGS_VEPA = IPVLAN_F_VEPA,
        _NETDEV_IPVLAN_FLAGS_MAX,
        _NETDEV_IPVLAN_FLAGS_INVALID = -1
} IPVlanFlags;

typedef struct IPVlan {
        NetDev meta;

        IPVlanMode mode;
        IPVlanFlags flags;
} IPVlan;

DEFINE_NETDEV_CAST(IPVLAN, IPVlan);
DEFINE_NETDEV_CAST(IPVTAP, IPVlan);
extern const NetDevVTable ipvlan_vtable;
extern const NetDevVTable ipvtap_vtable;

const char *ipvlan_mode_to_string(IPVlanMode d) _const_;
IPVlanMode ipvlan_mode_from_string(const char *d) _pure_;

const char *ipvlan_flags_to_string(IPVlanFlags d) _const_;
IPVlanFlags ipvlan_flags_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipvlan_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_ipvlan_flags);

IPVlanMode link_get_ipvlan_mode(Link *link);
