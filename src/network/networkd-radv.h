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

typedef enum RADVPrefixDelegation {
        RADV_PREFIX_DELEGATION_NONE,
        RADV_PREFIX_DELEGATION_STATIC,
        RADV_PREFIX_DELEGATION_DHCP6,
        RADV_PREFIX_DELEGATION_BOTH,
        _RADV_PREFIX_DELEGATION_MAX,
        _RADV_PREFIX_DELEGATION_INVALID = -1,
} RADVPrefixDelegation;

struct Prefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_prefix *radv_prefix;
        sd_radv_route_prefix *radv_route_prefix;

        LIST_FIELDS(Prefix, prefixes);
        LIST_FIELDS(Prefix, route_prefixes);
};

int prefix_new(Prefix **ret);
void prefix_free(Prefix *prefix);

DEFINE_NETWORK_SECTION_FUNCTIONS(Prefix, prefix_free);

int route_prefix_new(Prefix **ret);
void route_prefix_free(Prefix *prefix);

DEFINE_NETWORK_SECTION_FUNCTIONS(Prefix, route_prefix_free);

int radv_emit_dns(Link *link);
int radv_configure(Link *link);

const char* radv_prefix_delegation_to_string(RADVPrefixDelegation i) _const_;
RADVPrefixDelegation radv_prefix_delegation_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_router_prefix_delegation);
CONFIG_PARSER_PROTOTYPE(config_parse_router_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_dns);
CONFIG_PARSER_PROTOTYPE(config_parse_radv_search_domains);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_route_prefix_lifetime);
