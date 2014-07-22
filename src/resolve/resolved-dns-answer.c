/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "resolved-dns-answer.h"
#include "resolved-dns-domain.h"

DnsAnswer *dns_answer_new(unsigned n) {
        DnsAnswer *a;

        assert(n > 0);

        a = malloc0(offsetof(DnsAnswer, rrs) + sizeof(DnsResourceRecord*) * n);
        if (!a)
                return NULL;

        a->n_ref = 1;
        a->n_allocated = n;

        return a;
}

DnsAnswer *dns_answer_ref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);
        a->n_ref++;
        return a;
}

DnsAnswer *dns_answer_unref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);

        if (a->n_ref == 1) {
                unsigned i;

                for (i = 0; i < a->n_rrs; i++)
                        dns_resource_record_unref(a->rrs[i]);

                free(a);
        } else
                a->n_ref--;

        return NULL;
}

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr) {
        unsigned i;
        int r;

        assert(a);
        assert(rr);

        for (i = 0; i < a->n_rrs; i++) {
                r = dns_resource_record_equal(a->rrs[i], rr);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Entry already exists, keep the entry with
                         * the higher RR, or the one with TTL 0 */

                        if (rr->ttl == 0 || (rr->ttl > a->rrs[i]->ttl && a->rrs[i]->ttl != 0)) {
                                dns_resource_record_ref(rr);
                                dns_resource_record_unref(a->rrs[i]);
                                a->rrs[i] = rr;
                        }

                        return 0;
                }
        }

        if (a->n_rrs >= a->n_allocated)
                return -ENOSPC;

        a->rrs[a->n_rrs++] = dns_resource_record_ref(rr);
        return 1;
}

int dns_answer_contains(DnsAnswer *a, DnsResourceKey *key) {
        unsigned i;
        int r;

        assert(a);
        assert(key);

        for (i = 0; i < a->n_rrs; i++) {
                r = dns_resource_key_match_rr(key, a->rrs[i]);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

int dns_answer_find_soa(DnsAnswer *a, DnsResourceKey *key, DnsResourceRecord **ret) {
        unsigned i;

        assert(a);
        assert(key);
        assert(ret);

        for (i = 0; i < a->n_rrs; i++) {

                if (a->rrs[i]->key->class != DNS_CLASS_IN)
                        continue;

                if (a->rrs[i]->key->type != DNS_TYPE_SOA)
                        continue;

                if (dns_name_endswith(DNS_RESOURCE_KEY_NAME(key), DNS_RESOURCE_KEY_NAME(a->rrs[i]->key))) {
                        *ret = a->rrs[i];
                        return 1;
                }
        }

        return 0;
}

DnsAnswer *dns_answer_merge(DnsAnswer *a, DnsAnswer *b) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret = NULL;
        DnsAnswer *k;
        unsigned i;
        int r;

        if (a && (!b || b->n_rrs <= 0))
                return dns_answer_ref(a);
        if ((!a || a->n_rrs <= 0) && b)
                return dns_answer_ref(b);

        ret = dns_answer_new((a ? a->n_rrs : 0) + (b ? b->n_rrs : 0));
        if (!ret)
                return NULL;

        if (a) {
                for (i = 0; i < a->n_rrs; i++) {
                        r = dns_answer_add(ret, a->rrs[i]);
                        if (r < 0)
                                return NULL;
                }
        }

        if (b) {
                for (i = 0; i < b->n_rrs; i++) {
                        r = dns_answer_add(ret, b->rrs[i]);
                        if (r < 0)
                                return NULL;
                }
        }

        k = ret;
        ret = NULL;

        return k;
}
