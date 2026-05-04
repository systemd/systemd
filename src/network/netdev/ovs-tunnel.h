/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-forward.h"

typedef struct OVSTunnel {
        NetDev meta;

        char *bridge;
        char *type;                /* vxlan, geneve, gre, stt */
        union in_addr_union remote;
        int remote_family;
        union in_addr_union local;
        int local_family;
        uint32_t key;
        bool key_set;
        uint16_t destination_port;
        uint8_t tos;
        uint8_t ttl;
        int dont_fragment;        /* tristate */
} OVSTunnel;

DEFINE_NETDEV_CAST(OVS_TUNNEL, OVSTunnel);
extern const NetDevVTable ovs_tunnel_vtable;
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_tunnel_type);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_tunnel_address);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_tunnel_key);
