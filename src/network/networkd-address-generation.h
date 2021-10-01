/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"
#include "set.h"

typedef struct Link Link;

int generate_ipv6_eui_64_address(const Link *link, struct in6_addr *ret);

int ndisc_router_generate_addresses(Link *link, struct in6_addr *address, uint8_t prefixlen, Set **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_address_generation_type);
