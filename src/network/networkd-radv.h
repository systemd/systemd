/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <inttypes.h>
#include <stdbool.h>

#include "sd-radv.h"

#include "in-addr-util.h"
#include "conf-parser.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Network Network;

typedef enum RADVPrefixDelegation {
        RADV_PREFIX_DELEGATION_NONE   = 0,
        RADV_PREFIX_DELEGATION_STATIC = 1 << 0,
        RADV_PREFIX_DELEGATION_DHCP6  = 1 << 1,
        RADV_PREFIX_DELEGATION_BOTH   = RADV_PREFIX_DELEGATION_STATIC | RADV_PREFIX_DELEGATION_DHCP6,
        _RADV_PREFIX_DELEGATION_MAX,
        _RADV_PREFIX_DELEGATION_INVALID = -EINVAL,
} RADVPrefixDelegation;

typedef struct Prefix {
        Network *network;
        ConfigSection *section;

        struct in6_addr prefix;
        uint8_t prefixlen;
        usec_t preferred_lifetime;
        usec_t valid_lifetime;

        bool onlink;
        bool address_auto_configuration;

        bool assign;
        uint32_t route_metric;
        Set *tokens;
} Prefix;

typedef struct RoutePrefix {
        Network *network;
        ConfigSection *section;

        struct in6_addr prefix;
        uint8_t prefixlen;
        usec_t lifetime;
} RoutePrefix;

Prefix *prefix_free(Prefix *prefix);
RoutePrefix *route_prefix_free(RoutePrefix *prefix);

void network_drop_invalid_prefixes(Network *network);
void network_drop_invalid_route_prefixes(Network *network);
void network_adjust_radv(Network *network);

int link_request_radv_addresses(Link *link);

bool link_radv_enabled(Link *link);
int radv_start(Link *link);
int radv_update_mac(Link *link);
int radv_add_prefix(Link *link, const struct in6_addr *prefix, uint8_t prefix_len,
                    usec_t lifetime_preferred_usec, usec_t lifetime_valid_usec);

int link_request_radv(Link *link);

const char* radv_prefix_delegation_to_string(RADVPrefixDelegation i) _const_;
RADVPrefixDelegation radv_prefix_delegation_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_router_prefix_delegation);
CONFIG_PARSER_PROTOTYPE(config_parse_router_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_router_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_metric);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_token);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix_lifetime);
