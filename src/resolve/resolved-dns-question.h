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

typedef struct DnsQuestion DnsQuestion;

#include "macro.h"
#include "resolved-dns-rr.h"

/* A simple array of resource keys */

struct DnsQuestion {
        unsigned n_ref;
        unsigned n_keys, n_allocated;
        DnsResourceKey* keys[0];
};

DnsQuestion *dns_question_new(unsigned n);
DnsQuestion *dns_question_ref(DnsQuestion *q);
DnsQuestion *dns_question_unref(DnsQuestion *q);

int dns_question_new_address(DnsQuestion **ret, int family, const char *name);
int dns_question_new_reverse(DnsQuestion **ret, int family, const union in_addr_union *a);
int dns_question_new_service(DnsQuestion **ret, const char *name, bool with_txt);

int dns_question_add(DnsQuestion *q, DnsResourceKey *key);

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain);
int dns_question_matches_cname(DnsQuestion *q, DnsResourceRecord *rr, const char* search_domain);
int dns_question_is_valid_for_query(DnsQuestion *q);
int dns_question_contains(DnsQuestion *a, DnsResourceKey *k);
int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b);

int dns_question_cname_redirect(DnsQuestion *q, const DnsResourceRecord *cname, DnsQuestion **ret);

const char *dns_question_first_name(DnsQuestion *q);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuestion*, dns_question_unref);

#define _DNS_QUESTION_FOREACH(u, key, q)                                \
        for (unsigned UNIQ_T(i, u) = ({                                 \
                                (key) = ((q) && (q)->n_keys > 0) ? (q)->keys[0] : NULL; \
                                0;                                      \
                        });                                             \
             (q) && (UNIQ_T(i, u) < (q)->n_keys);                       \
             UNIQ_T(i, u)++, (key) = (UNIQ_T(i, u) < (q)->n_keys ? (q)->keys[UNIQ_T(i, u)] : NULL))

#define DNS_QUESTION_FOREACH(key, q) _DNS_QUESTION_FOREACH(UNIQ, key, q)
