/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include "conf-parser.h"
#include "networkd-address.h"
#include "networkd-link.h"

typedef struct Prefix Prefix;

struct Prefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_prefix *radv_prefix;

        LIST_FIELDS(Prefix, prefixes);
};

int prefix_new(Prefix **ret);
void prefix_free(Prefix *prefix);
int prefix_new_static(Network *network, const char *filename, unsigned section, Prefix **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(Prefix*, prefix_free);

CONFIG_PARSER_PROTOTYPE(config_parse_router_prefix_delegation);
CONFIG_PARSER_PROTOTYPE(config_parse_router_preference);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_prefix_lifetime);

int radv_emit_dns(Link *link);
int radv_configure(Link *link);
