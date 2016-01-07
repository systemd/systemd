/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

typedef struct DnsTrustAnchor DnsTrustAnchor;

#include "hashmap.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"

/* This contains a fixed database mapping domain names to DS or DNSKEY records. */

struct DnsTrustAnchor {
        Hashmap *positive_by_key;
        Set *negative_by_name;
};

int dns_trust_anchor_load(DnsTrustAnchor *d);
void dns_trust_anchor_flush(DnsTrustAnchor *d);

int dns_trust_anchor_lookup_positive(DnsTrustAnchor *d, const DnsResourceKey* key, DnsAnswer **answer);
int dns_trust_anchor_lookup_negative(DnsTrustAnchor *d, const char *name);

int dns_trust_anchor_check_revoked(DnsTrustAnchor *d, DnsResourceRecord *dnskey, DnsAnswer *rrs);
