/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

#include "hash-funcs.h"
#include "macro.h"
#include "util.h"

union in_addr_union {
        struct in_addr in;
        struct in6_addr in6;
};

struct in_addr_data {
        int family;
        union in_addr_union address;
};

bool in4_addr_is_null(const struct in_addr *a);
int in_addr_is_null(int family, const union in_addr_union *u);

int in_addr_is_multicast(int family, const union in_addr_union *u);

bool in4_addr_is_link_local(const struct in_addr *a);
int in_addr_is_link_local(int family, const union in_addr_union *u);

bool in4_addr_is_localhost(const struct in_addr *a);
int in_addr_is_localhost(int family, const union in_addr_union *u);

int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b);
int in_addr_prefix_intersect(int family, const union in_addr_union *a, unsigned aprefixlen, const union in_addr_union *b, unsigned bprefixlen);
int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen);
int in_addr_to_string(int family, const union in_addr_union *u, char **ret);
int in_addr_ifindex_to_string(int family, const union in_addr_union *u, int ifindex, char **ret);
int in_addr_from_string(int family, const char *s, union in_addr_union *ret);
int in_addr_from_string_auto(const char *s, int *ret_family, union in_addr_union *ret);
int in_addr_ifindex_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex);
unsigned char in4_addr_netmask_to_prefixlen(const struct in_addr *addr);
struct in_addr* in4_addr_prefixlen_to_netmask(struct in_addr *addr, unsigned char prefixlen);
int in4_addr_default_prefixlen(const struct in_addr *addr, unsigned char *prefixlen);
int in4_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *mask);
int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen);
int in_addr_prefix_covers(int family, const union in_addr_union *prefix, unsigned char prefixlen, const union in_addr_union *address);
int in_addr_parse_prefixlen(int family, const char *p, unsigned char *ret);
int in_addr_prefix_from_string_internal(const char *p, bool use_default_prefixlen, int family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen);
int in_addr_prefix_from_string_auto_internal(const char *p, bool use_default_prefixlen, int *ret_family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen);
static inline int in_addr_prefix_from_string(const char *p, int family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen) {
        return in_addr_prefix_from_string_internal(p, false, family, ret_prefix, ret_prefixlen);
}
static inline int in_addr_prefix_from_string_auto(const char *p, int *ret_family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen) {
        return in_addr_prefix_from_string_auto_internal(p, false, ret_family, ret_prefix, ret_prefixlen);
}
static inline int in_addr_default_prefix_from_string(const char *p, int family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen) {
        return in_addr_prefix_from_string_internal(p, true, family, ret_prefix, ret_prefixlen);
}
static inline int in_addr_default_prefix_from_string_auto(const char *p, int *ret_family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen) {
        return in_addr_prefix_from_string_auto_internal(p, true, ret_family, ret_prefix, ret_prefixlen);
}

static inline size_t FAMILY_ADDRESS_SIZE(int family) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        return family == AF_INET6 ? 16 : 4;
}

#define IN_ADDR_NULL ((union in_addr_union) {})

void in_addr_data_hash_func(const void *p, struct siphash *state);
int in_addr_data_compare_func(const void *a, const void *b);
extern const struct hash_ops in_addr_data_hash_ops;
