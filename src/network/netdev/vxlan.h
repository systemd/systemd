/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct VxLan VxLan;

#include "in-addr-util.h"
#include "netdev/netdev.h"

#define VXLAN_VID_MAX (1u << 24) - 1
#define VXLAN_FLOW_LABEL_MAX_MASK 0xFFFFFU

struct VxLan {
        NetDev meta;

        uint64_t id;

        int remote_family;
        int local_family;

        union in_addr_union remote;
        union in_addr_union local;

        unsigned tos;
        unsigned ttl;
        unsigned max_fdb;
        unsigned flow_label;

        uint16_t dest_port;

        usec_t fdb_ageing;

        bool learning;
        bool arp_proxy;
        bool route_short_circuit;
        bool l2miss;
        bool l3miss;
        bool udpcsum;
        bool udp6zerocsumtx;
        bool udp6zerocsumrx;
        bool remote_csum_tx;
        bool remote_csum_rx;
        bool group_policy;

        struct ifla_vxlan_port_range port_range;
};

DEFINE_NETDEV_CAST(VXLAN, VxLan);
extern const NetDevVTable vxlan_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_vxlan_address);
CONFIG_PARSER_PROTOTYPE(config_parse_port_range);
CONFIG_PARSER_PROTOTYPE(config_parse_flow_label);
