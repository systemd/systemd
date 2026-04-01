/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

size_t serialize_in_addrs(FILE *f,
                          const struct in_addr *addresses,
                          size_t size,
                          bool *with_leading_space,
                          bool (*predicate)(const struct in_addr *addr));
int deserialize_in_addrs(struct in_addr **ret, const char *string);
void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses,
                         size_t size,
                         bool *with_leading_space);
int deserialize_in6_addrs(struct in6_addr **ret, const char *string);

int serialize_dnr(FILE *f, const sd_dns_resolver *dnr, size_t n_dnr, bool *with_leading_space);
int deserialize_dnr(sd_dns_resolver **ret, const char *string);
