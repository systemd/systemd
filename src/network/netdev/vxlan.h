/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct VxLan VxLan;

#include <linux/if_link.h>

#include "in-addr-util.h"
#include "netdev-util.h"
#include "netdev.h"

#define VXLAN_VID_MAX (1u << 24) - 1
#define VXLAN_FLOW_LABEL_MAX_MASK 0xFFFFFU

typedef enum VxLanDF {
        NETDEV_VXLAN_DF_NO = VXLAN_DF_UNSET,
        NETDEV_VXLAN_DF_YES = VXLAN_DF_SET,
        NETDEV_VXLAN_DF_INHERIT = VXLAN_DF_INHERIT,
        _NETDEV_VXLAN_DF_MAX,
        _NETDEV_VXLAN_DF_INVALID = -EINVAL,
} VxLanDF;

struct VxLan {
        NetDev meta;

        uint32_t vni;

        int remote_family;
        int local_family;
        int group_family;

        VxLanDF df;

        NetDevLocalAddressType local_type;
        union in_addr_union local;
        union in_addr_union remote;
        union in_addr_union group;

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
        bool generic_protocol_extension;
        bool inherit;
        bool independent;

        struct ifla_vxlan_port_range port_range;
};

DEFINE_NETDEV_CAST(VXLAN, VxLan);
extern const NetDevVTable vxlan_vtable;

const char* df_to_string(VxLanDF d) _const_;
VxLanDF df_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_vxlan_address);
CONFIG_PARSER_PROTOTYPE(config_parse_port_range);
CONFIG_PARSER_PROTOTYPE(config_parse_flow_label);
CONFIG_PARSER_PROTOTYPE(config_parse_df);
CONFIG_PARSER_PROTOTYPE(config_parse_vxlan_ttl);
