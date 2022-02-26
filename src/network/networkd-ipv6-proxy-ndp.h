/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Network Network;
typedef struct Request Request;

void network_adjust_ipv6_proxy_ndp(Network *network);

int link_request_static_ipv6_proxy_ndp_addresses(Link *link);
int ipv6_proxy_ndp_address_process_request(Request *req, Link *link, struct in6_addr *address);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_proxy_ndp_address);
