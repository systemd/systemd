/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"
#include "set.h"

struct in_addr_prefix {
        int family;
        uint8_t prefixlen;
        union in_addr_union address;
};

int in_addr_prefix_add(Set **prefixes, const struct in_addr_prefix *prefix);
int in_addr_prefixes_reduce(Set *prefixes);
int in_addr_prefixes_merge(Set **dest, Set *src);
/* Returns true if a set contains the two items necessary for "any" (0.0.0.0/0 and ::/0). */
bool in_addr_prefixes_is_any(Set *prefixes);

extern const struct hash_ops in_addr_prefix_hash_ops;
extern const struct hash_ops in_addr_prefix_hash_ops_free;

CONFIG_PARSER_PROTOTYPE(config_parse_in_addr_prefixes);
