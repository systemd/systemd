/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct MacVlan MacVlan;

#include "macvlan-util.h"
#include "netdev.h"
#include "set.h"

struct MacVlan {
        NetDev meta;

        MacVlanMode mode;
        Set *match_source_mac;

        uint32_t bc_queue_length;
};

DEFINE_NETDEV_CAST(MACVLAN, MacVlan);
DEFINE_NETDEV_CAST(MACVTAP, MacVlan);
extern const NetDevVTable macvlan_vtable;
extern const NetDevVTable macvtap_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_macvlan_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_macvlan_broadcast_queue_size);
