/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/if_link.h>

#include "ipvlan-util.h"
#include "netdev.h"

typedef struct IPVlan {
        NetDev meta;

        IPVlanMode mode;
        IPVlanFlags flags;
} IPVlan;

DEFINE_NETDEV_CAST(IPVLAN, IPVlan);
DEFINE_NETDEV_CAST(IPVTAP, IPVlan);
extern const NetDevVTable ipvlan_vtable;
extern const NetDevVTable ipvtap_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_ipvlan_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_ipvlan_flags);

IPVlanMode link_get_ipvlan_mode(Link *link);
