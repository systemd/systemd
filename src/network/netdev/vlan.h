/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "netdev.h"

typedef struct VLan {
        NetDev meta;

        uint16_t id;
        int protocol;

        int gvrp;
        int mvrp;
        int loose_binding;
        int reorder_hdr;

        Set *egress_qos_maps;
        Set *ingress_qos_maps;
} VLan;

DEFINE_NETDEV_CAST(VLAN, VLan);
extern const NetDevVTable vlan_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_vlan_qos_maps);
