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

#include "resolved-dns-cache.h"

/* Never cache more than 1K entries */
#define CACHE_MAX 1024

/* We never keep any item longer than 10min in our cache */
#define CACHE_TTL_MAX_USEC (10 * USEC_PER_MINUTE)

static void dns_cache_item_free(DnsCacheItem *i) {
        if (!i)
                return;

        dns_resource_record_unref(i->rr);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsCacheItem*, dns_cache_item_free);

static void dns_cache_item_remove_and_free(DnsCache *c, DnsCacheItem *i) {
        DnsCacheItem *first;

        assert(c);

        if (!i)
                return;

        first = hashmap_get(c->rrsets, i->rr->key);
        LIST_REMOVE(rrsets, first, i);

        if (first)
                assert_se(hashmap_replace(c->rrsets, first->rr->key, first) >= 0);
        else
                hashmap_remove(c->rrsets, i->rr->key);

        prioq_remove(c->expire, i, &i->expire_prioq_idx);

        dns_cache_item_free(i);
}

void dns_cache_flush(DnsCache *c) {
        DnsCacheItem *i;

        assert(c);

        while ((i = hashmap_first(c->rrsets)))
                dns_cache_item_remove_and_free(c, i);

        assert(hashmap_size(c->rrsets) == 0);
        assert(prioq_size(c->expire) == 0);

        hashmap_free(c->rrsets);
        c->rrsets = NULL;

        prioq_free(c->expire);
        c->expire = NULL;
}

void dns_cache_remove(DnsCache *c, DnsResourceKey *key) {
        DnsCacheItem *i;

        assert(c);
        assert(key);

        while ((i = hashmap_get(c->rrsets, key)))
                dns_cache_item_remove_and_free(c, i);
}

static void dns_cache_make_space(DnsCache *c, unsigned add) {
        assert(c);

        if (add <= 0)
                return;

        /* Makes space for n new entries. Note that we actually allow
         * the cache to grow beyond CACHE_MAX, but only when we shall
         * add more RRs to the cache than CACHE_MAX at once. In that
         * case the cache will be emptied completely otherwise. */

        for (;;) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                DnsCacheItem *i;

                if (prioq_size(c->expire) <= 0)
                        break;

                if (prioq_size(c->expire) + add < CACHE_MAX)
                        break;

                i = prioq_peek(c->expire);
                assert(i);

                /* Take an extra reference to the key so that it
                 * doesn't go away in the middle of the remove call */
                key = dns_resource_key_ref(i->rr->key);
                dns_cache_remove(c, key);
        }
}

void dns_cache_prune(DnsCache *c) {
        usec_t t = 0;

        assert(c);

        /* Remove all entries that are past their TTL */

        for (;;) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                DnsCacheItem *i;
                usec_t ttl;

                i = prioq_peek(c->expire);
                if (!i)
                        break;

                ttl = i->rr->ttl * USEC_PER_SEC;
                if (ttl > CACHE_TTL_MAX_USEC)
                        ttl = CACHE_TTL_MAX_USEC;

                if (t <= 0)
                        t = now(CLOCK_MONOTONIC);

                if (i->timestamp + ttl > t)
                        break;

                /* Take an extra reference to the key so that it
                 * doesn't go away in the middle of the remove call */
                key = dns_resource_key_ref(i->rr->key);
                dns_cache_remove(c, key);
        }
}

static int dns_cache_item_prioq_compare_func(const void *a, const void *b) {
        usec_t t, z;
        const DnsCacheItem *x = a, *y = b;

        t = x->timestamp + x->rr->ttl * USEC_PER_SEC;
        z = y->timestamp + y->rr->ttl * USEC_PER_SEC;

        if (t < z)
                return -1;
        if (t > z)
                return 1;
        return 0;
}

static void dns_cache_item_update(DnsCache *c, DnsCacheItem *i, DnsResourceRecord *rr, usec_t timestamp) {
        assert(c);
        assert(i);
        assert(rr);

        if (!i->rrsets_prev) {
                /* We are the first item in the list, we need to
                 * update the key used in the hashmap */

                assert_se(hashmap_replace(c->rrsets, rr->key, i) >= 0);
        }

        dns_resource_record_ref(rr);
        dns_resource_record_unref(i->rr);
        i->rr = rr;

        i->timestamp = timestamp;
        prioq_reshuffle(c->expire, i, &i->expire_prioq_idx);
}

static DnsCacheItem* dns_cache_get(DnsCache *c, DnsResourceRecord *rr) {
        DnsCacheItem *i;

        assert(c);
        assert(rr);

        LIST_FOREACH(rrsets, i, hashmap_get(c->rrsets, rr->key))
                if (dns_resource_record_equal(i->rr, rr))
                        return i;

        return NULL;
}

int dns_cache_put(DnsCache *c, DnsResourceRecord *rr, usec_t timestamp) {
        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        DnsCacheItem *first = NULL, *existing;
        int r;

        assert(c);
        assert(rr);

        /* New TTL is 0? Delete the entry... */
        if (rr->ttl <= 0) {
                dns_cache_remove(c, rr->key);
                return 0;
        }

        /* Entry exists already? Update TTL and timestamp */
        existing = dns_cache_get(c, rr);
        if (existing) {
                dns_cache_item_update(c, existing, rr, timestamp);
                return 0;
        }

        /* Otherwise, add the new RR */
        r = prioq_ensure_allocated(&c->expire, dns_cache_item_prioq_compare_func);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&c->rrsets, dns_resource_key_hash_func, dns_resource_key_compare_func);
        if (r < 0)
                return r;

        dns_cache_make_space(c, 1);

        i = new0(DnsCacheItem, 1);
        if (!i)
                return -ENOMEM;

        i->rr = dns_resource_record_ref(rr);
        i->timestamp = timestamp;
        i->expire_prioq_idx = PRIOQ_IDX_NULL;

        r = prioq_put(c->expire, i, &i->expire_prioq_idx);
        if (r < 0)
                return r;

        first = hashmap_get(c->rrsets, i->rr->key);
        if (first) {
                LIST_PREPEND(rrsets, first, i);
                assert_se(hashmap_replace(c->rrsets, first->rr->key, first) >= 0);
        } else {
                r = hashmap_put(c->rrsets, i->rr->key, i);
                if (r < 0) {
                        prioq_remove(c->expire, i, &i->expire_prioq_idx);
                        return r;
                }
        }

        i = NULL;

        return 0;
}

int dns_cache_put_answer(DnsCache *c, DnsAnswer *answer, usec_t timestamp) {
        unsigned i, added = 0;
        int r;

        assert(c);
        assert(answer);

        /* First iteration, delete all matching old RRs, so that we
         * only keep complete rrsets in place. */
        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->rrs[i]->key);

        dns_cache_make_space(c, answer->n_rrs);

        /* Second iteration, add in new RRs */
        for (added = 0; added < answer->n_rrs; added++) {
                if (timestamp <= 0)
                        timestamp = now(CLOCK_MONOTONIC);

                r = dns_cache_put(c, answer->rrs[added], timestamp);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        for (i = 0; i < added; i++)
                dns_cache_remove(c, answer->rrs[i]->key);

        return r;
}

int dns_cache_lookup(DnsCache *c, DnsQuestion *q, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned i, n = 0;
        int r;

        assert(c);
        assert(q);
        assert(ret);

        if (q->n_keys <= 0) {
                *ret = NULL;
                return 0;
        }

        for (i = 0; i < q->n_keys; i++) {
                DnsCacheItem *j;

                j = hashmap_get(c->rrsets, q->keys[i]);
                if (!j) {
                        /* If one question cannot be answered we need to refresh */
                        *ret = NULL;
                        return 0;
                }

                LIST_FOREACH(rrsets, j, j)
                        n++;
        }

        assert(n > 0);

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        for (i = 0; i < q->n_keys; i++) {
                DnsCacheItem *j;

                j = hashmap_get(c->rrsets, q->keys[i]);
                LIST_FOREACH(rrsets, j, j) {
                        r = dns_answer_add(answer, j->rr);
                        if (r < 0)
                                return r;
                }
        }

        assert(n >= answer->n_rrs);

        *ret = answer;
        answer = NULL;

        return n;
}
