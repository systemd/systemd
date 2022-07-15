/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Geneve Geneve;

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-network.h"

#define GENEVE_VID_MAX (1u << 24) - 1

typedef enum GeneveDF {
        NETDEV_GENEVE_DF_NO = GENEVE_DF_UNSET,
        NETDEV_GENEVE_DF_YES = GENEVE_DF_SET,
        NETDEV_GENEVE_DF_INHERIT = GENEVE_DF_INHERIT,
        _NETDEV_GENEVE_DF_MAX,
        _NETDEV_GENEVE_DF_INVALID = -EINVAL,
} GeneveDF;

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
        bool inherit;

        GeneveDF geneve_df;
        union in_addr_union remote;
};

DEFINE_NETDEV_CAST(GENEVE, Geneve);
extern const NetDevVTable geneve_vtable;

const char *geneve_df_to_string(GeneveDF d) _const_;
GeneveDF geneve_df_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_geneve_vni);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_address);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_flow_label);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_df);
CONFIG_PARSER_PROTOTYPE(config_parse_geneve_ttl);
