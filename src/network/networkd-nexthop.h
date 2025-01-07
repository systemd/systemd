/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc.
 */

#pragma once

#include <inttypes.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;
typedef struct NextHop NextHop;
typedef int (*nexthop_netlink_handler_t)(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                NextHop *nexthop);

struct NextHop {
        Network *network;
        Manager *manager;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;
        union in_addr_union provider; /* DHCP server or router address */

        unsigned n_ref;

        /* struct nhmsg */
        int family;
        uint8_t protocol;
        uint32_t flags;

        /* attributes */
        uint32_t id; /* NHA_ID */
        Hashmap *group; /* NHA_GROUP */
        bool blackhole; /* NHA_BLACKHOLE */
        int ifindex; /* NHA_OIF */
        struct in_addr_data gw; /* NHA_GATEWAY, gw.family is only used by conf parser. */

        /* Only used in conf parser and nexthop_section_verify(). */
        int onlink;

        /* For managing routes and nexthops that depend on this nexthop. */
        Set *nexthops;
        Set *routes;
};

void log_nexthop_debug(const NextHop *nexthop, const char *str, Manager *manager);

int nexthop_new(NextHop **ret);
NextHop* nexthop_ref(NextHop *nexthop);
NextHop* nexthop_unref(NextHop *nexthop);
DEFINE_SECTION_CLEANUP_FUNCTIONS(NextHop, nexthop_unref);

int nexthop_remove(NextHop *nexthop, Manager *manager);
int nexthop_remove_and_cancel(NextHop *nexthop, Manager *manager);

int network_drop_invalid_nexthops(Network *network);

int link_drop_nexthops(Link *link, bool only_static);
static inline int link_drop_unmanaged_nexthops(Link *link) {
        return link_drop_nexthops(link, /* only_static = */ false);
}
static inline int link_drop_static_nexthops(Link *link) {
        return link_drop_nexthops(link, /* only_static = */ true);
}
void link_forget_nexthops(Link *link);

int nexthop_configure_handler_internal(sd_netlink_message *m, Link *link, const char *error_msg);
int link_request_nexthop(
                Link *link,
                const NextHop *nexthop,
                unsigned *message_counter,
                nexthop_netlink_handler_t netlink_handler);
int link_request_static_nexthops(Link *link, bool only_ipv4);

int nexthop_get_by_id(Manager *manager, uint32_t id, NextHop **ret);
int nexthop_get_request_by_id(Manager *manager, uint32_t id, Request **ret);
int nexthop_is_ready(Manager *manager, uint32_t id, NextHop **ret);
int manager_rtnl_process_nexthop(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);
int manager_build_nexthop_ids(Manager *manager);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(NextHop, nexthop);

typedef enum NextHopConfParserType {
        NEXTHOP_ID,
        NEXTHOP_GATEWAY,
        NEXTHOP_FAMILY,
        NEXTHOP_ONLINK,
        NEXTHOP_BLACKHOLE,
        NEXTHOP_GROUP,
        _NEXTHOP_CONF_PARSER_MAX,
        _NEXTHOP_CONF_PARSER_INVALID = -EINVAL,
} NextHopConfParserType;

CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_section);
