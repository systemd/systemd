/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc.
 */

#pragma once

#include "conf-parser.h"
#include "macro.h"

typedef struct NextHop NextHop;
typedef struct NetworkConfigSection NetworkConfigSection;

#include "networkd-network.h"
#include "networkd-util.h"

struct NextHop {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        unsigned char protocol;

        int family;
        uint32_t oif;
        uint32_t id;

        union in_addr_union gw;

        LIST_FIELDS(NextHop, nexthops);
};

extern const struct hash_ops nexthop_hash_ops;

int nexthop_new(NextHop **ret);
void nexthop_free(NextHop *nexthop);
int nexthop_configure(NextHop *nexthop, Link *link, link_netlink_message_handler_t callback);
int nexthop_remove(NextHop *nexthop, Link *link, link_netlink_message_handler_t callback);

int nexthop_get(Link *link, NextHop *in, NextHop **ret);
int nexthop_add(Link *link, NextHop *in, NextHop **ret);
int nexthop_add_foreign(Link *link, NextHop *in, NextHop **ret);
bool nexthop_equal(NextHop *r1, NextHop *r2);

int nexthop_section_verify(NextHop *nexthop);

DEFINE_NETWORK_SECTION_FUNCTIONS(NextHop, nexthop_free);

CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_id);
CONFIG_PARSER_PROTOTYPE(config_parse_nexthop_gateway);
