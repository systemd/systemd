/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct VLan VLan;

#include "netdev.h"
#include "set.h"

struct VLan {
        NetDev meta;

        uint16_t id;
        int protocol;

        int gvrp;
        int mvrp;
        int loose_binding;
        int reorder_hdr;

        Set *egress_qos_maps;
        Set *ingress_qos_maps;
};

DEFINE_NETDEV_CAST(VLAN, VLan);
extern const NetDevVTable vlan_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_vlan_qos_maps);
