/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <linux/batman_adv.h>

#include "conf-parser.h"
#include "netdev.h"

#define BATADV_GENL_NAME "batadv"

typedef enum BatadvGatewayModes {
        BATADV_GATEWAY_MODE_OFF = BATADV_GW_MODE_OFF,
        BATADV_GATEWAY_MODE_CLIENT = BATADV_GW_MODE_CLIENT,
        BATADV_GATEWAY_MODE_SERVER = BATADV_GW_MODE_SERVER,
        _BATADV_GATEWAY_MODE_MAX,
        _BATADV_GATEWAY_MODE_INVALID = -EINVAL,
} BatadvGatewayModes;

typedef enum BatadvRoutingAlgorithm {
        BATADV_ROUTING_ALGORITHM_BATMAN_V,
        BATADV_ROUTING_ALGORITHM_BATMAN_IV,
        _BATADV_ROUTING_ALGORITHM_MAX,
        _BATADV_ROUTING_ALGORITHM_INVALID = -EINVAL,
} BatadvRoutingAlgorithm;

typedef struct Batadv {
        NetDev meta;

        BatadvGatewayModes gateway_mode;
        uint32_t gateway_bandwidth_down;
        uint32_t gateway_bandwidth_up;
        uint8_t hop_penalty;
        BatadvRoutingAlgorithm routing_algorithm;
        usec_t originator_interval;
        bool aggregation;
        bool bridge_loop_avoidance;
        bool distributed_arp_table;
        bool fragmentation;
} BatmanAdvanced;

DEFINE_NETDEV_CAST(BATADV, BatmanAdvanced);
extern const NetDevVTable batadv_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_batadv_gateway_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_batadv_routing_algorithm);
CONFIG_PARSER_PROTOTYPE(config_parse_badadv_bandwidth);
