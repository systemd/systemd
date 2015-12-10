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

typedef struct DnsAnswer DnsAnswer;
typedef struct DnsAnswerItem DnsAnswerItem;

#include "macro.h"
#include "resolved-dns-rr.h"

/* A simple array of resource records. We keep track of the
 * originating ifindex for each RR where that makes sense, so that we
 * can qualify A and AAAA RRs referring to a local link with the
 * right ifindex.
 *
 * Note that we usually encode the empty answer as a simple NULL. */

struct DnsAnswerItem {
        DnsResourceRecord *rr;
        int ifindex;
};

struct DnsAnswer {
        unsigned n_ref;
        unsigned n_rrs, n_allocated;
        DnsAnswerItem items[0];
};

DnsAnswer *dns_answer_new(unsigned n);
DnsAnswer *dns_answer_ref(DnsAnswer *a);
DnsAnswer *dns_answer_unref(DnsAnswer *a);

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr, int ifindex);
int dns_answer_add_extend(DnsAnswer **a, DnsResourceRecord *rr, int ifindex);
int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl);

int dns_answer_match_key(DnsAnswer *a, const DnsResourceKey *key);
int dns_answer_contains_rr(DnsAnswer *a, DnsResourceRecord *rr);

int dns_answer_find_soa(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret);
int dns_answer_find_cname_or_dname(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret);

int dns_answer_merge(DnsAnswer *a, DnsAnswer *b, DnsAnswer **ret);
int dns_answer_extend(DnsAnswer **a, DnsAnswer *b);

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local);

int dns_answer_reserve(DnsAnswer **a, unsigned n_free);
int dns_answer_reserve_or_clone(DnsAnswer **a, unsigned n_free);

int dns_answer_remove_by_key(DnsAnswer **a, const DnsResourceKey *key);
int dns_answer_copy_by_key(DnsAnswer **a, DnsAnswer *source, const DnsResourceKey *key);

static inline unsigned dns_answer_size(DnsAnswer *a) {
        return a ? a->n_rrs : 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsAnswer*, dns_answer_unref);

#define _DNS_ANSWER_FOREACH(q, kk, a)                                   \
        for (unsigned UNIQ_T(i, q) = ({                                 \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++, (kk) = (UNIQ_T(i, q) < (a)->n_rrs ? (a)->items[UNIQ_T(i, q)].rr : NULL))

#define DNS_ANSWER_FOREACH(kk, a) _DNS_ANSWER_FOREACH(UNIQ, kk, a)

#define _DNS_ANSWER_FOREACH_IFINDEX(q, kk, ifi, a)                      \
        for (unsigned UNIQ_T(i, q) = ({                                 \
                                (kk) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].rr : NULL; \
                                (ifi) = ((a) && (a)->n_rrs > 0) ? (a)->items[0].ifindex : 0; \
                                0;                                      \
                        });                                             \
             (a) && (UNIQ_T(i, q) < (a)->n_rrs);                        \
             UNIQ_T(i, q)++, (kk) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].rr : NULL), (ifi) = ((UNIQ_T(i, q) < (a)->n_rrs) ? (a)->items[UNIQ_T(i, q)].ifindex : 0))

#define DNS_ANSWER_FOREACH_IFINDEX(kk, ifindex, a) _DNS_ANSWER_FOREACH_IFINDEX(UNIQ, kk, ifindex, a)
