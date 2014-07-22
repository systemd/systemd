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
#include "resolved-dns-packet.h"

/* Never cache more than 1K entries */
#define CACHE_MAX 1024

/* We never keep any item longer than 10min in our cache */
#define CACHE_TTL_MAX_USEC (10 * USEC_PER_MINUTE)

static void dns_cache_item_free(DnsCacheItem *i) {
        if (!i)
                return;

        dns_resource_record_unref(i->rr);
        dns_resource_key_unref(i->key);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsCacheItem*, dns_cache_item_free);

static void dns_cache_item_remove_and_free(DnsCache *c, DnsCacheItem *i) {
        DnsCacheItem *first;

        assert(c);

        if (!i)
                return;

        first = hashmap_get(c->by_key, i->key);
        LIST_REMOVE(by_key, first, i);

        if (first)
                assert_se(hashmap_replace(c->by_key, first->key, first) >= 0);
        else
                hashmap_remove(c->by_key, i->key);

        prioq_remove(c->by_expiry, i, &i->prioq_idx);

        dns_cache_item_free(i);
}

void dns_cache_flush(DnsCache *c) {
        DnsCacheItem *i;

        assert(c);

        while ((i = hashmap_first(c->by_key)))
                dns_cache_item_remove_and_free(c, i);

        assert(hashmap_size(c->by_key) == 0);
        assert(prioq_size(c->by_expiry) == 0);

        hashmap_free(c->by_key);
        c->by_key = NULL;

        prioq_free(c->by_expiry);
        c->by_expiry = NULL;
}

static void dns_cache_remove(DnsCache *c, DnsResourceKey *key) {
        DnsCacheItem *i;

        assert(c);
        assert(key);

        while ((i = hashmap_get(c->by_key, key)))
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

                if (prioq_size(c->by_expiry) <= 0)
                        break;

                if (prioq_size(c->by_expiry) + add < CACHE_MAX)
                        break;

                i = prioq_peek(c->by_expiry);
                assert(i);

                /* Take an extra reference to the key so that it
                 * doesn't go away in the middle of the remove call */
                key = dns_resource_key_ref(i->key);
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

                i = prioq_peek(c->by_expiry);
                if (!i)
                        break;

                if (t <= 0)
                        t = now(CLOCK_MONOTONIC);

                if (i->until > t)
                        break;

                /* Take an extra reference to the key so that it
                 * doesn't go away in the middle of the remove call */
                key = dns_resource_key_ref(i->key);
                dns_cache_remove(c, key);
        }
}

static int dns_cache_item_prioq_compare_func(const void *a, const void *b) {
        const DnsCacheItem *x = a, *y = b;

        if (x->until < y->until)
                return -1;
        if (x->until > y->until)
                return 1;
        return 0;
}

static int init_cache(DnsCache *c) {
        int r;

        r = prioq_ensure_allocated(&c->by_expiry, dns_cache_item_prioq_compare_func);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&c->by_key, dns_resource_key_hash_func, dns_resource_key_compare_func);
        if (r < 0)
                return r;

        return r;
}

static int dns_cache_link_item(DnsCache *c, DnsCacheItem *i) {
        DnsCacheItem *first;
        int r;

        assert(c);
        assert(i);

        r = prioq_put(c->by_expiry, i, &i->prioq_idx);
        if (r < 0)
                return r;

        first = hashmap_get(c->by_key, i->key);
        if (first) {
                LIST_PREPEND(by_key, first, i);
                assert_se(hashmap_replace(c->by_key, first->key, first) >= 0);
        } else {
                r = hashmap_put(c->by_key, i->key, i);
                if (r < 0) {
                        prioq_remove(c->by_expiry, i, &i->prioq_idx);
                        return r;
                }
        }

        return 0;
}

static DnsCacheItem* dns_cache_get(DnsCache *c, DnsResourceRecord *rr) {
        DnsCacheItem *i;

        assert(c);
        assert(rr);

        LIST_FOREACH(by_key, i, hashmap_get(c->by_key, rr->key))
                if (i->rr && dns_resource_record_equal(i->rr, rr))
                        return i;

        return NULL;
}

static void dns_cache_item_update_positive(DnsCache *c, DnsCacheItem *i, DnsResourceRecord *rr, usec_t timestamp) {
        assert(c);
        assert(i);
        assert(rr);

        i->type = DNS_CACHE_POSITIVE;

        if (!i->by_key_prev) {
                /* We are the first item in the list, we need to
                 * update the key used in the hashmap */

                assert_se(hashmap_replace(c->by_key, rr->key, i) >= 0);
        }

        dns_resource_record_ref(rr);
        dns_resource_record_unref(i->rr);
        i->rr = rr;

        dns_resource_key_unref(i->key);
        i->key = dns_resource_key_ref(rr->key);

        i->until = timestamp + MIN(rr->ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);

        prioq_reshuffle(c->by_expiry, i, &i->prioq_idx);
}

static int dns_cache_put_positive(DnsCache *c, DnsResourceRecord *rr, usec_t timestamp) {
        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        DnsCacheItem *existing;
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
                dns_cache_item_update_positive(c, existing, rr, timestamp);
                return 0;
        }

        /* Otherwise, add the new RR */
        r = init_cache(c);
        if (r < 0)
                return r;

        dns_cache_make_space(c, 1);

        i = new0(DnsCacheItem, 1);
        if (!i)
                return -ENOMEM;

        i->type = DNS_CACHE_POSITIVE;
        i->key = dns_resource_key_ref(rr->key);
        i->rr = dns_resource_record_ref(rr);
        i->until = timestamp + MIN(i->rr->ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);
        i->prioq_idx = PRIOQ_IDX_NULL;

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        i = NULL;
        return 0;
}

static int dns_cache_put_negative(DnsCache *c, DnsResourceKey *key, int rcode, usec_t timestamp, uint32_t soa_ttl) {
        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        int r;

        assert(c);
        assert(key);

        dns_cache_remove(c, key);

        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        r = init_cache(c);
        if (r < 0)
                return r;

        dns_cache_make_space(c, 1);

        i = new0(DnsCacheItem, 1);
        if (!i)
                return -ENOMEM;

        i->type = rcode == DNS_RCODE_SUCCESS ? DNS_CACHE_NODATA : DNS_CACHE_NXDOMAIN;
        i->key = dns_resource_key_ref(key);
        i->until = timestamp + MIN(soa_ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);
        i->prioq_idx = PRIOQ_IDX_NULL;

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        i = NULL;
        return 0;
}

int dns_cache_put(DnsCache *c, DnsQuestion *q, int rcode, DnsAnswer *answer, usec_t timestamp) {
        unsigned i;
        int r;

        assert(c);
        assert(answer);

        /* First, delete all matching old RRs, so that we only keep
         * complete by_key in place. */
        for (i = 0; i < q->n_keys; i++)
                dns_cache_remove(c, q->keys[i]);
        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->rrs[i]->key);

        /* We only care for positive replies and NXDOMAINs, on all
         * other replies we will simply flush the respective entries,
         * and that's it */

        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        /* Make some space for our new entries */
        dns_cache_make_space(c, answer->n_rrs + q->n_keys);

        if (timestamp <= 0)
                timestamp = now(CLOCK_MONOTONIC);

        /* Second, add in positive entries for all contained RRs */
        for (i = 0; i < answer->n_rrs; i++) {
                r = dns_cache_put_positive(c, answer->rrs[i], timestamp);
                if (r < 0)
                        goto fail;
        }

        /* Third, add in negative entries for all keys with no RR */
        for (i = 0; i < q->n_keys; i++) {
                DnsResourceRecord *soa = NULL;

                r = dns_answer_contains(answer, q->keys[i]);
                if (r < 0)
                        goto fail;
                if (r > 0)
                        continue;

                r = dns_answer_find_soa(answer, q->keys[i], &soa);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        continue;

                r = dns_cache_put_negative(c, q->keys[i], rcode, timestamp, MIN(soa->soa.minimum, soa->ttl));
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        for (i = 0; i < q->n_keys; i++)
                dns_cache_remove(c, q->keys[i]);
        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->rrs[i]->key);

        return r;
}

int dns_cache_lookup(DnsCache *c, DnsQuestion *q, int *rcode, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned i, n = 0;
        int r;
        bool nxdomain = false;

        assert(c);
        assert(q);
        assert(ret);

        if (q->n_keys <= 0) {
                *ret = NULL;
                *rcode = 0;
                return 0;
        }

        for (i = 0; i < q->n_keys; i++) {
                DnsCacheItem *j;

                j = hashmap_get(c->by_key, q->keys[i]);
                if (!j) {
                        /* If one question cannot be answered we need to refresh */
                        *ret = NULL;
                        *rcode = 0;
                        return 0;
                }

                LIST_FOREACH(by_key, j, j) {
                        if (j->rr)
                                n++;
                        else if (j->type == DNS_CACHE_NXDOMAIN)
                                nxdomain = true;
                }
        }

        if (n <= 0) {
                *ret = NULL;
                *rcode = nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SUCCESS;
                return 1;
        }

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        for (i = 0; i < q->n_keys; i++) {
                DnsCacheItem *j;

                j = hashmap_get(c->by_key, q->keys[i]);
                LIST_FOREACH(by_key, j, j) {
                        if (j->rr) {
                                r = dns_answer_add(answer, j->rr);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        *ret = answer;
        *rcode = DNS_RCODE_SUCCESS;
        answer = NULL;

        return n;
}
