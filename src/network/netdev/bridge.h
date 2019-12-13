/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <netinet/in.h>
#include <linux/if_bridge.h>

#include "conf-parser.h"
#include "netdev.h"

typedef struct Bridge {
        NetDev meta;

        int mcast_querier;
        int mcast_snooping;
        int vlan_filtering;
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
        MULTICAST_ROUTER_NONE            = MDB_RTR_TYPE_DISABLED,
        MULTICAST_ROUTER_TEMPORARY_QUERY = MDB_RTR_TYPE_TEMP_QUERY,
        MULTICAST_ROUTER_PERMANENT       = MDB_RTR_TYPE_PERM,
        MULTICAST_ROUTER_TEMPORARY       = MDB_RTR_TYPE_TEMP,
        _MULTICAST_ROUTER_MAX,
        _MULTICAST_ROUTER_INVALID = -1,
} MulticastRouter;

DEFINE_NETDEV_CAST(BRIDGE, Bridge);
extern const NetDevVTable bridge_vtable;

int link_set_bridge(Link *link);

const char* multicast_router_to_string(MulticastRouter i) _const_;
MulticastRouter multicast_router_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_multicast_router);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_igmp_version);
