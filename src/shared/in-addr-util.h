/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/in.h>

#include "macro.h"
#include "util.h"

union in_addr_union {
        struct in_addr in;
        struct in6_addr in6;
};

int in_addr_is_null(int family, const union in_addr_union *u);
int in_addr_is_link_local(int family, const union in_addr_union *u);
int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b);
int in_addr_prefix_intersect(int family, const union in_addr_union *a, unsigned aprefixlen, const union in_addr_union *b, unsigned bprefixlen);
int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen);
int in_addr_to_string(int family, const union in_addr_union *u, char **ret);
int in_addr_from_string(int family, const char *s, union in_addr_union *ret);
int in_addr_from_string_auto(const char *s, int *family, union in_addr_union *ret);
unsigned char in_addr_netmask_to_prefixlen(const struct in_addr *addr);
struct in_addr* in_addr_prefixlen_to_netmask(struct in_addr *addr, unsigned char prefixlen);
int in_addr_default_prefixlen(const struct in_addr *addr, unsigned char *prefixlen);
int in_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *mask);
int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen);

static inline size_t FAMILY_ADDRESS_SIZE(int family) {
        assert(family == AF_INET || family == AF_INET6);
        return family == AF_INET6 ? 16 : 4;
}

#define IN_ADDR_NULL ((union in_addr_union) {})
