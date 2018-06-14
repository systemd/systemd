/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014 Tom Gundersen
***/

#include <net/ethernet.h>
#include <stdbool.h>

#include "hash-funcs.h"

#define ETHER_ADDR_FORMAT_STR "%02X%02X%02X%02X%02X%02X"
#define ETHER_ADDR_FORMAT_VAL(x) (x).ether_addr_octet[0], (x).ether_addr_octet[1], (x).ether_addr_octet[2], (x).ether_addr_octet[3], (x).ether_addr_octet[4], (x).ether_addr_octet[5]

#define ETHER_ADDR_TO_STRING_MAX (3*6)
char* ether_addr_to_string(const struct ether_addr *addr, char buffer[ETHER_ADDR_TO_STRING_MAX]);

int ether_addr_compare(const void *a, const void *b);
static inline bool ether_addr_equal(const struct ether_addr *a, const struct ether_addr *b) {
        return ether_addr_compare(a, b) == 0;
}

#define ETHER_ADDR_NULL ((const struct ether_addr){})

static inline bool ether_addr_is_null(const struct ether_addr *addr) {
        return ether_addr_equal(addr, &ETHER_ADDR_NULL);
}

int ether_addr_from_string(const char *s, struct ether_addr *ret);

extern const struct hash_ops ether_addr_hash_ops;
