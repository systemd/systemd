/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

#define IPV4LL_ROUTE_METRIC 2048

typedef struct Link Link;
typedef struct Network Network;

bool link_ipv4ll_enabled(Link *link);

int ipv4ll_configure(Link *link);
int link_drop_ipv4ll_config(Link *link, Network *network);
int ipv4ll_update_mac(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv4ll);
CONFIG_PARSER_PROTOTYPE(config_parse_ipv4ll_address);
