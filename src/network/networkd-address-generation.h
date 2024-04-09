/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "hashmap.h"
#include "in-addr-util.h"

typedef struct Address Address;
typedef struct IPv6Token IPv6Token;
typedef struct Link Link;

IPv6Token* ipv6_token_ref(IPv6Token *token);
IPv6Token* ipv6_token_unref(IPv6Token *token);

int dhcp_pd_generate_addresses(Link *link, const struct in6_addr *prefix, Hashmap **ret);
int ndisc_generate_addresses(Link *link, const struct in6_addr *prefix, uint8_t prefixlen, Hashmap **ret);
int radv_generate_addresses(Link *link, Set *tokens, const struct in6_addr *prefix, uint8_t prefixlen, Hashmap **ret);

int regenerate_address(Address *address, Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_address_generation_type);
