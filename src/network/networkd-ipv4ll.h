/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

#define IPV4LL_ROUTE_METRIC 2048

typedef struct Link Link;

int ipv4ll_configure(Link *link);
int ipv4ll_update_mac(Link *link);
int link_serialize_ipv4ll(Link *link, FILE *f);
int link_deserialize_ipv4ll(Link *link, const char *ipv4ll_address);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv4ll);
