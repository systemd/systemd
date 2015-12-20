/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "alloc-util.h"
#include "resolved-dns-trust-anchor.h"

/* The DS RR from https://data.iana.org/root-anchors/root-anchors.xml */
static const uint8_t root_digest[] =
        { 0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60, 0x73, 0x71, 0x60,
          0x7A, 0x1A, 0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD, 0xDE, 0x32, 0xF2, 0x4E, 0x8F, 0xB5 };

int dns_trust_anchor_load(DnsTrustAnchor *d) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(d);

        r = hashmap_ensure_allocated(&d->by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        if (hashmap_get(d->by_key, &DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_DS, ".")))
                return 0;

        /* Add the RR from https://data.iana.org/root-anchors/root-anchors.xml */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, "");
        if (!rr)
                return -ENOMEM;

        rr->ds.key_tag = 19036;
        rr->ds.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        rr->ds.digest_type = DNSSEC_DIGEST_SHA256;
        rr->ds.digest_size = sizeof(root_digest);
        rr->ds.digest = memdup(root_digest, rr->ds.digest_size);
        if (!rr->ds.digest)
                return  -ENOMEM;

        answer = dns_answer_new(1);
        if (!answer)
                return -ENOMEM;

        r = dns_answer_add(answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
        if (r < 0)
                return r;

        r = hashmap_put(d->by_key, rr->key, answer);
        if (r < 0)
                return r;

        answer = NULL;
        return 0;
}

void dns_trust_anchor_flush(DnsTrustAnchor *d) {
        DnsAnswer *a;

        assert(d);

        while ((a = hashmap_steal_first(d->by_key)))
                dns_answer_unref(a);

        d->by_key = hashmap_free(d->by_key);
}

int dns_trust_anchor_lookup(DnsTrustAnchor *d, DnsResourceKey *key, DnsAnswer **ret) {
        DnsAnswer *a;

        assert(d);
        assert(key);
        assert(ret);

        /* We only serve DS and DNSKEY RRs. */
        if (!IN_SET(key->type, DNS_TYPE_DS, DNS_TYPE_DNSKEY))
                return 0;

        a = hashmap_get(d->by_key, key);
        if (!a)
                return 0;

        *ret = dns_answer_ref(a);
        return 1;
}
