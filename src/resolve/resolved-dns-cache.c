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

typedef enum DnsCacheItemType DnsCacheItemType;
typedef struct DnsCacheItem DnsCacheItem;

enum DnsCacheItemType {
        DNS_CACHE_POSITIVE,
        DNS_CACHE_NODATA,
        DNS_CACHE_NXDOMAIN,
};

struct DnsCacheItem {
        DnsResourceKey *key;
        DnsResourceRecord *rr;
        usec_t until;
        DnsCacheItemType type;
        unsigned prioq_idx;
        int owner_family;
        union in_addr_union owner_address;
        LIST_FIELDS(DnsCacheItem, by_key);
};

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

        c->by_key = hashmap_free(c->by_key);
        c->by_expiry = prioq_free(c->by_expiry);
}

static bool dns_cache_remove(DnsCache *c, DnsResourceKey *key) {
        DnsCacheItem *i;
        bool exist = false;

        assert(c);
        assert(key);

        while ((i = hashmap_get(c->by_key, key))) {
                dns_cache_item_remove_and_free(c, i);
                exist = true;
        }

        return exist;
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
                        t = now(clock_boottime_or_monotonic());

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

static int dns_cache_init(DnsCache *c) {
        int r;

        assert(c);

        r = prioq_ensure_allocated(&c->by_expiry, dns_cache_item_prioq_compare_func);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&c->by_key, &dns_resource_key_hash_ops);
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
                if (i->rr && dns_resource_record_equal(i->rr, rr) > 0)
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

static int dns_cache_put_positive(
                DnsCache *c,
                DnsResourceRecord *rr,
                usec_t timestamp,
                int owner_family,
                const union in_addr_union *owner_address) {

        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        _cleanup_free_ char *key_str = NULL;
        DnsCacheItem *existing;
        int r;

        assert(c);
        assert(rr);
        assert(owner_address);

        /* New TTL is 0? Delete the entry... */
        if (rr->ttl <= 0) {
                if (dns_cache_remove(c, rr->key)) {
                        r = dns_resource_key_to_string(rr->key, &key_str);
                        if (r < 0)
                                return r;

                        log_debug("Removed zero TTL entry from cache: %s", key_str);
                }

                return 0;
        }

        if (rr->key->class == DNS_CLASS_ANY)
                return 0;
        if (rr->key->type == DNS_TYPE_ANY)
                return 0;

        /* Entry exists already? Update TTL and timestamp */
        existing = dns_cache_get(c, rr);
        if (existing) {
                dns_cache_item_update_positive(c, existing, rr, timestamp);
                return 0;
        }

        /* Otherwise, add the new RR */
        r = dns_cache_init(c);
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
        i->owner_family = owner_family;
        i->owner_address = *owner_address;

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        r = dns_resource_key_to_string(i->key, &key_str);
        if (r < 0)
                return r;

        log_debug("Added cache entry for %s", key_str);

        i = NULL;
        return 0;
}

static int dns_cache_put_negative(
                DnsCache *c,
                DnsResourceKey *key,
                int rcode,
                usec_t timestamp,
                uint32_t soa_ttl,
                int owner_family,
                const union in_addr_union *owner_address) {

        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        _cleanup_free_ char *key_str = NULL;
        int r;

        assert(c);
        assert(key);
        assert(owner_address);

        dns_cache_remove(c, key);

        if (key->class == DNS_CLASS_ANY)
                return 0;
        if (key->type == DNS_TYPE_ANY)
                return 0;
        if (soa_ttl <= 0) {
                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Ignored negative cache entry with zero SOA TTL: %s", key_str);

                return 0;
        }

        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        r = dns_cache_init(c);
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
        i->owner_family = owner_family;
        i->owner_address = *owner_address;

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        r = dns_resource_key_to_string(i->key, &key_str);
        if (r < 0)
                return r;

        log_debug("Added %s cache entry for %s", i->type == DNS_CACHE_NODATA ? "NODATA" : "NXDOMAIN", key_str);

        i = NULL;
        return 0;
}

int dns_cache_put(
                DnsCache *c,
                DnsQuestion *q,
                int rcode,
                DnsAnswer *answer,
                unsigned max_rrs,
                usec_t timestamp,
                int owner_family,
                const union in_addr_union *owner_address) {

        unsigned cache_keys, i;
        int r;

        assert(c);

        if (q) {
                /* First, if we were passed a question, delete all matching old RRs,
                 * so that we only keep complete by_key in place. */
                for (i = 0; i < q->n_keys; i++)
                        dns_cache_remove(c, q->keys[i]);
        }

        if (!answer)
                return 0;

        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->items[i].rr->key);

        /* We only care for positive replies and NXDOMAINs, on all
         * other replies we will simply flush the respective entries,
         * and that's it */

        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        cache_keys = answer->n_rrs;

        if (q)
                cache_keys += q->n_keys;

        /* Make some space for our new entries */
        dns_cache_make_space(c, cache_keys);

        if (timestamp <= 0)
                timestamp = now(clock_boottime_or_monotonic());

        /* Second, add in positive entries for all contained RRs */
        for (i = 0; i < MIN(max_rrs, answer->n_rrs); i++) {
                r = dns_cache_put_positive(c, answer->items[i].rr, timestamp, owner_family, owner_address);
                if (r < 0)
                        goto fail;
        }

        if (!q)
                return 0;

        /* Third, add in negative entries for all keys with no RR */
        for (i = 0; i < q->n_keys; i++) {
                DnsResourceRecord *soa = NULL;

                r = dns_answer_contains(answer, q->keys[i]);
                if (r < 0)
                        goto fail;
                if (r > 0)
                        continue;

                /* See https://tools.ietf.org/html/rfc2308, which
                 * say that a matching SOA record in the packet
                 * is used to to enable negative caching. */

                r = dns_answer_find_soa(answer, q->keys[i], &soa);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        continue;

                r = dns_cache_put_negative(c, q->keys[i], rcode, timestamp, MIN(soa->soa.minimum, soa->ttl), owner_family, owner_address);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        if (q) {
                for (i = 0; i < q->n_keys; i++)
                        dns_cache_remove(c, q->keys[i]);
        }

        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->items[i].rr->key);

        return r;
}

int dns_cache_lookup(DnsCache *c, DnsResourceKey *key, int *rcode, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned n = 0;
        int r;
        bool nxdomain = false;
        _cleanup_free_ char *key_str = NULL;
        DnsCacheItem *j, *first;

        assert(c);
        assert(key);
        assert(rcode);
        assert(ret);

        if (key->type == DNS_TYPE_ANY ||
            key->class == DNS_CLASS_ANY) {

                /* If we have ANY lookups we simply refresh */

                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Ignoring cache for ANY lookup: %s", key_str);

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                return 0;
        }

        first = hashmap_get(c->by_key, key);
        if (!first) {
                /* If one question cannot be answered we need to refresh */

                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Cache miss for %s", key_str);

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                return 0;
        }

        LIST_FOREACH(by_key, j, first) {
                if (j->rr)
                        n++;
                else if (j->type == DNS_CACHE_NXDOMAIN)
                        nxdomain = true;
        }

        r = dns_resource_key_to_string(key, &key_str);
        if (r < 0)
                return r;

        log_debug("%s cache hit for %s",
                  nxdomain ? "NXDOMAIN" :
                     n > 0 ? "Positive" : "NODATA",
                  key_str);

        if (n <= 0) {
                *ret = NULL;
                *rcode = nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SUCCESS;
                return 1;
        }

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        LIST_FOREACH(by_key, j, first) {
                if (!j->rr)
                        continue;

                r = dns_answer_add(answer, j->rr, 0);
                if (r < 0)
                        return r;
        }

        *ret = answer;
        *rcode = DNS_RCODE_SUCCESS;
        answer = NULL;

        return n;
}

int dns_cache_check_conflicts(DnsCache *cache, DnsResourceRecord *rr, int owner_family, const union in_addr_union *owner_address) {
        DnsCacheItem *i, *first;
        bool same_owner = true;

        assert(cache);
        assert(rr);

        dns_cache_prune(cache);

        /* See if there's a cache entry for the same key. If there
         * isn't there's no conflict */
        first = hashmap_get(cache->by_key, rr->key);
        if (!first)
                return 0;

        /* See if the RR key is owned by the same owner, if so, there
         * isn't a conflict either */
        LIST_FOREACH(by_key, i, first) {
                if (i->owner_family != owner_family ||
                    !in_addr_equal(owner_family, &i->owner_address, owner_address)) {
                        same_owner = false;
                        break;
                }
        }
        if (same_owner)
                return 0;

        /* See if there's the exact same RR in the cache. If yes, then
         * there's no conflict. */
        if (dns_cache_get(cache, rr))
                return 0;

        /* There's a conflict */
        return 1;
}

void dns_cache_dump(DnsCache *cache, FILE *f) {
        Iterator iterator;
        DnsCacheItem *i;
        int r;

        if (!cache)
                return;

        if (!f)
                f = stdout;

        HASHMAP_FOREACH(i, cache->by_key, iterator) {
                DnsCacheItem *j;

                LIST_FOREACH(by_key, j, i) {
                        _cleanup_free_ char *t = NULL;

                        fputc('\t', f);

                        if (j->rr) {
                                r = dns_resource_record_to_string(j->rr, &t);
                                if (r < 0) {
                                        log_oom();
                                        continue;
                                }

                                fputs(t, f);
                                fputc('\n', f);
                        } else {
                                r = dns_resource_key_to_string(j->key, &t);
                                if (r < 0) {
                                        log_oom();
                                        continue;
                                }

                                fputs(t, f);
                                fputs(" -- ", f);
                                fputs(j->type == DNS_CACHE_NODATA ? "NODATA" : "NXDOMAIN", f);
                                fputc('\n', f);
                        }
                }
        }
}

bool dns_cache_is_empty(DnsCache *cache) {
        if (!cache)
                return true;

        return hashmap_isempty(cache->by_key);
}
