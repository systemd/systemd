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

int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *soa = NULL;

        soa = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, name);
        if (!soa)
                return -ENOMEM;

        soa->ttl = ttl;

        soa->soa.mname = strdup(name);
        if (!soa->soa.mname)
                return -ENOMEM;

        soa->soa.rname = strappend("root.", name);
        if (!soa->soa.rname)
                return -ENOMEM;

        soa->soa.serial = 1;
        soa->soa.refresh = 1;
        soa->soa.retry = 1;
        soa->soa.expire = 1;
        soa->soa.minimum = ttl;

        return dns_answer_add(a, soa);
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

        /* For a SOA record we can never find a matching SOA record */
        if (key->type == DNS_TYPE_SOA)
                return 0;

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

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local) {
        DnsResourceRecord **rrs;
        unsigned i, start, end;
        assert(a);

        if (a->n_rrs <= 1)
                return;

        start = 0;
        end = a->n_rrs-1;

        /* RFC 4795, Section 2.6 suggests we should order entries
         * depending on whether the sender is a link-local address. */

        rrs = newa(DnsResourceRecord*, a->n_rrs);
        for (i = 0; i < a->n_rrs; i++) {

                if (a->rrs[i]->key->class == DNS_CLASS_IN &&
                    ((a->rrs[i]->key->type == DNS_TYPE_A && in_addr_is_link_local(AF_INET, (union in_addr_union*) &a->rrs[i]->a.in_addr) != prefer_link_local) ||
                     (a->rrs[i]->key->type == DNS_TYPE_AAAA && in_addr_is_link_local(AF_INET6, (union in_addr_union*) &a->rrs[i]->aaaa.in6_addr) != prefer_link_local)))
                        /* Order address records that are are not preferred to the end of the array */
                        rrs[end--] = a->rrs[i];
                else
                        /* Order all other records to the beginning of the array */
                        rrs[start++] = a->rrs[i];
        }

        assert(start == end+1);
        memcpy(a->rrs, rrs, sizeof(DnsResourceRecord*) * a->n_rrs);
}
