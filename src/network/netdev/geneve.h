/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct Geneve Geneve;

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-link.h"
#include "networkd-network.h"

#define GENEVE_VID_MAX (1u << 24) - 1

struct Geneve {
        NetDev meta;

        uint32_t id;
        uint32_t flow_label;

        int remote_family;

        uint8_t tos;
        uint8_t ttl;

        uint16_t dest_port;

        bool udpcsum;
        bool udp6zerocsumtx;
        bool udp6zerocsumrx;

        union in_addr_union remote;
};

DEFINE_NETDEV_CAST(GENEVE, Geneve);
extern const NetDevVTable geneve_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_geneve_vni);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_address);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_flow_label);
