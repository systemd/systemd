/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "ether-addr-util.h"

#define IPV4LL_ROUTE_METRIC 2048

typedef struct Link Link;

int ipv4ll_configure(Link *link);
int ipv4ll_update_mac(Link *link, struct hw_addr_data *old);
void ipv4ll_drop_mac(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv4ll);
