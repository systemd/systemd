/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include "conf-parser.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Prefix Prefix;
typedef struct RoutePrefix RoutePrefix;

typedef enum RADVPrefixDelegation {
        RADV_PREFIX_DELEGATION_NONE   = 0,
        RADV_PREFIX_DELEGATION_STATIC = 1 << 0,
        RADV_PREFIX_DELEGATION_DHCP6  = 1 << 1,
        RADV_PREFIX_DELEGATION_BOTH   = RADV_PREFIX_DELEGATION_STATIC | RADV_PREFIX_DELEGATION_DHCP6,
        _RADV_PREFIX_DELEGATION_MAX,
        _RADV_PREFIX_DELEGATION_INVALID = -1,
} RADVPrefixDelegation;

struct Prefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_prefix *radv_prefix;

        bool assign;

        LIST_FIELDS(Prefix, prefixes);
};

struct RoutePrefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_route_prefix *radv_route_prefix;

        LIST_FIELDS(RoutePrefix, route_prefixes);
};

void prefix_free(Prefix *prefix);

DEFINE_NETWORK_SECTION_FUNCTIONS(Prefix, prefix_free);

void route_prefix_free(RoutePrefix *prefix);

DEFINE_NETWORK_SECTION_FUNCTIONS(RoutePrefix, route_prefix_free);

int radv_emit_dns(Link *link);
int radv_configure(Link *link);
int radv_add_prefix(Link *link, const struct in6_addr *prefix, uint8_t prefix_len,
                    uint32_t lifetime_preferred, uint32_t lifetime_valid);

const char* radv_prefix_delegation_to_string(RADVPrefixDelegation i) _const_;
RADVPrefixDelegation radv_prefix_delegation_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_router_prefix_delegation);
CONFIG_PARSER_PROTOTYPE(config_parse_router_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_assign);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix_lifetime);
