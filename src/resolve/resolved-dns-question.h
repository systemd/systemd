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

#include "resolved-dns-rr.h"

/* A simple array of resources keys */

struct DnsQuestion {
        unsigned n_ref;
        unsigned n_keys, n_allocated;
        DnsResourceKey* keys[0];
};

DnsQuestion *dns_question_new(unsigned n);
DnsQuestion *dns_question_ref(DnsQuestion *q);
DnsQuestion *dns_question_unref(DnsQuestion *q);

int dns_question_add(DnsQuestion *q, DnsResourceKey *key);

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr);
int dns_question_matches_cname(DnsQuestion *q, DnsResourceRecord *rr);
int dns_question_is_valid(DnsQuestion *q);
int dns_question_is_superset(DnsQuestion *q, DnsQuestion *other);
int dns_question_contains(DnsQuestion *a, DnsResourceKey *k);
int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b);

int dns_question_cname_redirect(DnsQuestion *q, const char *name, DnsQuestion **ret);

int dns_question_endswith(DnsQuestion *q, const char *suffix);
int dns_question_extract_reverse_address(DnsQuestion *q, int *family, union in_addr_union *address);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsQuestion*, dns_question_unref);
