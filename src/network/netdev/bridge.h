/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "netdev.h"

#define LINK_BRIDGE_PORT_PRIORITY_INVALID 128U
#define LINK_BRIDGE_PORT_PRIORITY_MAX 63U

typedef struct Bridge {
        NetDev meta;

        int mcast_querier;
        int mcast_snooping;
        int vlan_filtering;
        int vlan_protocol;
        int stp;
        uint16_t priority;
        uint16_t group_fwd_mask;
        uint16_t default_pvid;
        uint8_t igmp_version;

        usec_t forward_delay;
        usec_t hello_time;
        usec_t max_age;
        usec_t ageing_time;
} Bridge;

typedef enum MulticastRouter {
        MULTICAST_ROUTER_NONE,
        MULTICAST_ROUTER_TEMPORARY_QUERY,
        MULTICAST_ROUTER_PERMANENT,
        MULTICAST_ROUTER_TEMPORARY,
        _MULTICAST_ROUTER_MAX,
        _MULTICAST_ROUTER_INVALID = -EINVAL,
} MulticastRouter;

DEFINE_NETDEV_CAST(BRIDGE, Bridge);
extern const NetDevVTable bridge_vtable;

const char* multicast_router_to_string(MulticastRouter i) _const_;
MulticastRouter multicast_router_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_multicast_router);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_igmp_version);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_port_priority);
