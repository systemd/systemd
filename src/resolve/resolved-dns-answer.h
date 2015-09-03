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

#include "resolved-dns-rr.h"

/* A simple array of resource records. We keep track of the
 * originating ifindex for each RR where that makes sense, so that we
 * can qualify A and AAAA RRs referring to a local link with the
 * right ifindex. */

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
int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl);
int dns_answer_contains(DnsAnswer *a, DnsResourceKey *key);
int dns_answer_match_soa(DnsResourceKey *key, DnsResourceKey *soa);
int dns_answer_find_soa(DnsAnswer *a, DnsResourceKey *key, DnsResourceRecord **ret);

DnsAnswer *dns_answer_merge(DnsAnswer *a, DnsAnswer *b);
void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local);

int dns_answer_reserve(DnsAnswer **a, unsigned n_free);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsAnswer*, dns_answer_unref);
