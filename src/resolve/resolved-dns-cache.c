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

#include <net/if.h>

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-packet.h"
#include "string-util.h"

/* Never cache more than 4K entries. RFC 1536, Section 5 suggests to
 * leave DNS caches unbounded, but that's crazy. */
#define CACHE_MAX 4096

/* We never keep any item longer than 2h in our cache */
#define CACHE_TTL_MAX_USEC (2 * USEC_PER_HOUR)

typedef enum DnsCacheItemType DnsCacheItemType;
typedef struct DnsCacheItem DnsCacheItem;

enum DnsCacheItemType {
        DNS_CACHE_POSITIVE,
        DNS_CACHE_NODATA,
        DNS_CACHE_NXDOMAIN,
};

struct DnsCacheItem {
        DnsCacheItemType type;
        DnsResourceKey *key;
        DnsResourceRecord *rr;

        usec_t until;
        bool authenticated:1;
        bool shared_owner:1;

        int ifindex;
        int owner_family;
        union in_addr_union owner_address;

        unsigned prioq_idx;
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

static void dns_cache_item_unlink_and_free(DnsCache *c, DnsCacheItem *i) {
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

static bool dns_cache_remove_by_rr(DnsCache *c, DnsResourceRecord *rr) {
        DnsCacheItem *first, *i;
        int r;

        first = hashmap_get(c->by_key, rr->key);
        LIST_FOREACH(by_key, i, first) {
                r = dns_resource_record_equal(i->rr, rr);
                if (r < 0)
                        return r;
                if (r > 0) {
                        dns_cache_item_unlink_and_free(c, i);
                        return true;
                }
        }

        return false;
}

static bool dns_cache_remove_by_key(DnsCache *c, DnsResourceKey *key) {
        DnsCacheItem *first, *i, *n;

        assert(c);
        assert(key);

        first = hashmap_remove(c->by_key, key);
        if (!first)
                return false;

        LIST_FOREACH_SAFE(by_key, i, n, first) {
                prioq_remove(c->by_expiry, i, &i->prioq_idx);
                dns_cache_item_free(i);
        }

        return true;
}

void dns_cache_flush(DnsCache *c) {
        DnsResourceKey *key;

        assert(c);

        while ((key = hashmap_first_key(c->by_key)))
                dns_cache_remove_by_key(c, key);

        assert(hashmap_size(c->by_key) == 0);
        assert(prioq_size(c->by_expiry) == 0);

        c->by_key = hashmap_free(c->by_key);
        c->by_expiry = prioq_free(c->by_expiry);
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
                dns_cache_remove_by_key(c, key);
        }
}

void dns_cache_prune(DnsCache *c) {
        usec_t t = 0;

        assert(c);

        /* Remove all entries that are past their TTL */

        for (;;) {
                DnsCacheItem *i;
                char key_str[DNS_RESOURCE_KEY_STRING_MAX];

                i = prioq_peek(c->by_expiry);
                if (!i)
                        break;

                if (t <= 0)
                        t = now(clock_boottime_or_monotonic());

                if (i->until > t)
                        break;

                /* Depending whether this is an mDNS shared entry
                 * either remove only this one RR or the whole RRset */
                log_debug("Removing %scache entry for %s (expired "USEC_FMT"s ago)",
                          i->shared_owner ? "shared " : "",
                          dns_resource_key_to_string(i->key, key_str, sizeof key_str),
                          (t - i->until) / USEC_PER_SEC);

                if (i->shared_owner)
                        dns_cache_item_unlink_and_free(c, i);
                else {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                        /* Take an extra reference to the key so that it
                         * doesn't go away in the middle of the remove call */
                        key = dns_resource_key_ref(i->key);
                        dns_cache_remove_by_key(c, key);
                }
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
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;

                /* Keep a reference to the original key, while we manipulate the list. */
                k = dns_resource_key_ref(first->key);

                /* Now, try to reduce the number of keys we keep */
                dns_resource_key_reduce(&first->key, &i->key);

                if (first->rr)
                        dns_resource_key_reduce(&first->rr->key, &i->key);
                if (i->rr)
                        dns_resource_key_reduce(&i->rr->key, &i->key);

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

static usec_t calculate_until(DnsResourceRecord *rr, uint32_t nsec_ttl, usec_t timestamp, bool use_soa_minimum) {
        uint32_t ttl;
        usec_t u;

        assert(rr);

        ttl = MIN(rr->ttl, nsec_ttl);
        if (rr->key->type == DNS_TYPE_SOA && use_soa_minimum) {
                /* If this is a SOA RR, and it is requested, clamp to
                 * the SOA's minimum field. This is used when we do
                 * negative caching, to determine the TTL for the
                 * negative caching entry.  See RFC 2308, Section
                 * 5. */

                if (ttl > rr->soa.minimum)
                        ttl = rr->soa.minimum;
        }

        u = ttl * USEC_PER_SEC;
        if (u > CACHE_TTL_MAX_USEC)
                u = CACHE_TTL_MAX_USEC;

        if (rr->expiry != USEC_INFINITY) {
                usec_t left;

                /* Make use of the DNSSEC RRSIG expiry info, if we
                 * have it */

                left = LESS_BY(rr->expiry, now(CLOCK_REALTIME));
                if (u > left)
                        u = left;
        }

        return timestamp + u;
}

static void dns_cache_item_update_positive(
                DnsCache *c,
                DnsCacheItem *i,
                DnsResourceRecord *rr,
                bool authenticated,
                bool shared_owner,
                usec_t timestamp,
                int ifindex,
                int owner_family,
                const union in_addr_union *owner_address) {

        assert(c);
        assert(i);
        assert(rr);
        assert(owner_address);

        i->type = DNS_CACHE_POSITIVE;

        if (!i->by_key_prev)
                /* We are the first item in the list, we need to
                 * update the key used in the hashmap */

                assert_se(hashmap_replace(c->by_key, rr->key, i) >= 0);

        dns_resource_record_ref(rr);
        dns_resource_record_unref(i->rr);
        i->rr = rr;

        dns_resource_key_unref(i->key);
        i->key = dns_resource_key_ref(rr->key);

        i->until = calculate_until(rr, (uint32_t) -1, timestamp, false);
        i->authenticated = authenticated;
        i->shared_owner = shared_owner;

        i->ifindex = ifindex;

        i->owner_family = owner_family;
        i->owner_address = *owner_address;

        prioq_reshuffle(c->by_expiry, i, &i->prioq_idx);
}

static int dns_cache_put_positive(
                DnsCache *c,
                DnsResourceRecord *rr,
                bool authenticated,
                bool shared_owner,
                usec_t timestamp,
                int ifindex,
                int owner_family,
                const union in_addr_union *owner_address) {

        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        DnsCacheItem *existing;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX], ifname[IF_NAMESIZE];
        int r, k;

        assert(c);
        assert(rr);
        assert(owner_address);

        /* Never cache pseudo RRs */
        if (dns_class_is_pseudo(rr->key->class))
                return 0;
        if (dns_type_is_pseudo(rr->key->type))
                return 0;

        /* New TTL is 0? Delete this specific entry... */
        if (rr->ttl <= 0) {
                k = dns_cache_remove_by_rr(c, rr);
                log_debug("%s: %s",
                          k > 0 ? "Removed zero TTL entry from cache" : "Not caching zero TTL cache entry",
                          dns_resource_key_to_string(rr->key, key_str, sizeof key_str));
                return 0;
        }

        /* Entry exists already? Update TTL, timestamp and owner*/
        existing = dns_cache_get(c, rr);
        if (existing) {
                dns_cache_item_update_positive(
                                c,
                                existing,
                                rr,
                                authenticated,
                                shared_owner,
                                timestamp,
                                ifindex,
                                owner_family,
                                owner_address);
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
        i->until = calculate_until(rr, (uint32_t) -1, timestamp, false);
        i->authenticated = authenticated;
        i->shared_owner = shared_owner;
        i->ifindex = ifindex;
        i->owner_family = owner_family;
        i->owner_address = *owner_address;
        i->prioq_idx = PRIOQ_IDX_NULL;

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        if (log_get_max_level() >= LOG_DEBUG) {
                _cleanup_free_ char *t = NULL;

                (void) in_addr_to_string(i->owner_family, &i->owner_address, &t);

                log_debug("Added positive %s%s cache entry for %s "USEC_FMT"s on %s/%s/%s",
                          i->authenticated ? "authenticated" : "unauthenticated",
                          i->shared_owner ? " shared" : "",
                          dns_resource_key_to_string(i->key, key_str, sizeof key_str),
                          (i->until - timestamp) / USEC_PER_SEC,
                          i->ifindex == 0 ? "*" : strna(if_indextoname(i->ifindex, ifname)),
                          af_to_name_short(i->owner_family),
                          strna(t));
        }

        i = NULL;
        return 0;
}

static int dns_cache_put_negative(
                DnsCache *c,
                DnsResourceKey *key,
                int rcode,
                bool authenticated,
                uint32_t nsec_ttl,
                usec_t timestamp,
                DnsResourceRecord *soa,
                int owner_family,
                const union in_addr_union *owner_address) {

        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        int r;

        assert(c);
        assert(key);
        assert(soa);
        assert(owner_address);

        /* Never cache pseudo RR keys. DNS_TYPE_ANY is particularly
         * important to filter out as we use this as a pseudo-type for
         * NXDOMAIN entries */
        if (dns_class_is_pseudo(key->class))
                return 0;
        if (dns_type_is_pseudo(key->type))
                return 0;

        if (nsec_ttl <= 0 || soa->soa.minimum <= 0 || soa->ttl <= 0) {
                log_debug("Not caching negative entry with zero SOA/NSEC/NSEC3 TTL: %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
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
        i->until = calculate_until(soa, nsec_ttl, timestamp, true);
        i->authenticated = authenticated;
        i->owner_family = owner_family;
        i->owner_address = *owner_address;
        i->prioq_idx = PRIOQ_IDX_NULL;

        if (i->type == DNS_CACHE_NXDOMAIN) {
                /* NXDOMAIN entries should apply equally to all types, so we use ANY as
                 * a pseudo type for this purpose here. */
                i->key = dns_resource_key_new(key->class, DNS_TYPE_ANY, dns_resource_key_name(key));
                if (!i->key)
                        return -ENOMEM;

                /* Make sure to remove any previous entry for this
                 * specific ANY key. (For non-ANY keys the cache data
                 * is already cleared by the caller.) Note that we
                 * don't bother removing positive or NODATA cache
                 * items in this case, because it would either be slow
                 * or require explicit indexing by name */
                dns_cache_remove_by_key(c, key);
        } else
                i->key = dns_resource_key_ref(key);

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        log_debug("Added %s cache entry for %s "USEC_FMT"s",
                  i->type == DNS_CACHE_NODATA ? "NODATA" : "NXDOMAIN",
                  dns_resource_key_to_string(i->key, key_str, sizeof key_str),
                  (i->until - timestamp) / USEC_PER_SEC);

        i = NULL;
        return 0;
}

static void dns_cache_remove_previous(
                DnsCache *c,
                DnsResourceKey *key,
                DnsAnswer *answer) {

        DnsResourceRecord *rr;
        DnsAnswerFlags flags;

        assert(c);

        /* First, if we were passed a key (i.e. on LLMNR/DNS, but
         * not on mDNS), delete all matching old RRs, so that we only
         * keep complete by_key in place. */
        if (key)
                dns_cache_remove_by_key(c, key);

        /* Second, flush all entries matching the answer, unless this
         * is an RR that is explicitly marked to be "shared" between
         * peers (i.e. mDNS RRs without the flush-cache bit set). */
        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {
                if ((flags & DNS_ANSWER_CACHEABLE) == 0)
                        continue;

                if (flags & DNS_ANSWER_SHARED_OWNER)
                        continue;

                dns_cache_remove_by_key(c, rr->key);
        }
}

static bool rr_eligible(DnsResourceRecord *rr) {
        assert(rr);

        /* When we see an NSEC/NSEC3 RR, we'll only cache it if it is from the lower zone, not the upper zone, since
         * that's where the interesting bits are (with exception of DS RRs). Of course, this way we cannot derive DS
         * existence from any cached NSEC/NSEC3, but that should be fine. */

        switch (rr->key->type) {

        case DNS_TYPE_NSEC:
                return !bitmap_isset(rr->nsec.types, DNS_TYPE_NS) ||
                        bitmap_isset(rr->nsec.types, DNS_TYPE_SOA);

        case DNS_TYPE_NSEC3:
                return !bitmap_isset(rr->nsec3.types, DNS_TYPE_NS) ||
                        bitmap_isset(rr->nsec3.types, DNS_TYPE_SOA);

        default:
                return true;
        }
}

int dns_cache_put(
                DnsCache *c,
                DnsResourceKey *key,
                int rcode,
                DnsAnswer *answer,
                bool authenticated,
                uint32_t nsec_ttl,
                usec_t timestamp,
                int owner_family,
                const union in_addr_union *owner_address) {

        DnsResourceRecord *soa = NULL, *rr;
        DnsAnswerFlags flags;
        unsigned cache_keys;
        int r, ifindex;

        assert(c);
        assert(owner_address);

        dns_cache_remove_previous(c, key, answer);

        /* We only care for positive replies and NXDOMAINs, on all
         * other replies we will simply flush the respective entries,
         * and that's it */
        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        if (dns_answer_size(answer) <= 0) {
                char key_str[DNS_RESOURCE_KEY_STRING_MAX];

                log_debug("Not caching negative entry without a SOA record: %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
                return 0;
        }

        cache_keys = dns_answer_size(answer);
        if (key)
                cache_keys++;

        /* Make some space for our new entries */
        dns_cache_make_space(c, cache_keys);

        if (timestamp <= 0)
                timestamp = now(clock_boottime_or_monotonic());

        /* Second, add in positive entries for all contained RRs */
        DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, answer) {
                if ((flags & DNS_ANSWER_CACHEABLE) == 0)
                        continue;

                r = rr_eligible(rr);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dns_cache_put_positive(
                                c,
                                rr,
                                flags & DNS_ANSWER_AUTHENTICATED,
                                flags & DNS_ANSWER_SHARED_OWNER,
                                timestamp,
                                ifindex,
                                owner_family, owner_address);
                if (r < 0)
                        goto fail;
        }

        if (!key) /* mDNS doesn't know negative caching, really */
                return 0;

        /* Third, add in negative entries if the key has no RR */
        r = dns_answer_match_key(answer, key, NULL);
        if (r < 0)
                goto fail;
        if (r > 0)
                return 0;

        /* But not if it has a matching CNAME/DNAME (the negative
         * caching will be done on the canonical name, not on the
         * alias) */
        r = dns_answer_find_cname_or_dname(answer, key, NULL, NULL);
        if (r < 0)
                goto fail;
        if (r > 0)
                return 0;

        /* See https://tools.ietf.org/html/rfc2308, which say that a
         * matching SOA record in the packet is used to enable
         * negative caching. */
        r = dns_answer_find_soa(answer, key, &soa, &flags);
        if (r < 0)
                goto fail;
        if (r == 0)
                return 0;

        /* Refuse using the SOA data if it is unsigned, but the key is
         * signed */
        if (authenticated && (flags & DNS_ANSWER_AUTHENTICATED) == 0)
                return 0;

        r = dns_cache_put_negative(
                        c,
                        key,
                        rcode,
                        authenticated,
                        nsec_ttl,
                        timestamp,
                        soa,
                        owner_family, owner_address);
        if (r < 0)
                goto fail;

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        if (key)
                dns_cache_remove_by_key(c, key);

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {
                if ((flags & DNS_ANSWER_CACHEABLE) == 0)
                        continue;

                dns_cache_remove_by_key(c, rr->key);
        }

        return r;
}

static DnsCacheItem *dns_cache_get_by_key_follow_cname_dname_nsec(DnsCache *c, DnsResourceKey *k) {
        DnsCacheItem *i;
        const char *n;
        int r;

        assert(c);
        assert(k);

        /* If we hit some OOM error, or suchlike, we don't care too
         * much, after all this is just a cache */

        i = hashmap_get(c->by_key, k);
        if (i)
                return i;

        n = dns_resource_key_name(k);

        /* Check if we have an NXDOMAIN cache item for the name, notice that we use
         * the pseudo-type ANY for NXDOMAIN cache items. */
        i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_ANY, n));
        if (i && i->type == DNS_CACHE_NXDOMAIN)
                return i;

        if (dns_type_may_redirect(k->type)) {
                /* Check if we have a CNAME record instead */
                i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_CNAME, n));
                if (i)
                        return i;

                /* OK, let's look for cached DNAME records. */
                for (;;) {
                        if (isempty(n))
                                return NULL;

                        i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_DNAME, n));
                        if (i)
                                return i;

                        /* Jump one label ahead */
                        r = dns_name_parent(&n);
                        if (r <= 0)
                                return NULL;
                }
        }

        if (k->type != DNS_TYPE_NSEC) {
                /* Check if we have an NSEC record instead for the name. */
                i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_NSEC, n));
                if (i)
                        return i;
        }

        return NULL;
}

int dns_cache_lookup(DnsCache *c, DnsResourceKey *key, bool clamp_ttl, int *rcode, DnsAnswer **ret, bool *authenticated) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        unsigned n = 0;
        int r;
        bool nxdomain = false;
        DnsCacheItem *j, *first, *nsec = NULL;
        bool have_authenticated = false, have_non_authenticated = false;
        usec_t current;

        assert(c);
        assert(key);
        assert(rcode);
        assert(ret);
        assert(authenticated);

        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                /* If we have ANY lookups we don't use the cache, so
                 * that the caller refreshes via the network. */

                log_debug("Ignoring cache for ANY lookup: %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));

                c->n_miss++;

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                return 0;
        }

        first = dns_cache_get_by_key_follow_cname_dname_nsec(c, key);
        if (!first) {
                /* If one question cannot be answered we need to refresh */

                log_debug("Cache miss for %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));

                c->n_miss++;

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                return 0;
        }

        LIST_FOREACH(by_key, j, first) {
                if (j->rr) {
                        if (j->rr->key->type == DNS_TYPE_NSEC)
                                nsec = j;

                        n++;
                } else if (j->type == DNS_CACHE_NXDOMAIN)
                        nxdomain = true;

                if (j->authenticated)
                        have_authenticated = true;
                else
                        have_non_authenticated = true;
        }

        if (nsec && !IN_SET(key->type, DNS_TYPE_NSEC, DNS_TYPE_DS)) {
                /* Note that we won't derive information for DS RRs from an NSEC, because we only cache NSEC RRs from
                 * the lower-zone of a zone cut, but the DS RRs are on the upper zone. */

                log_debug("NSEC NODATA cache hit for %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));

                /* We only found an NSEC record that matches our name.
                 * If it says the type doesn't exist report
                 * NODATA. Otherwise report a cache miss. */

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                *authenticated = nsec->authenticated;

                if (!bitmap_isset(nsec->rr->nsec.types, key->type) &&
                    !bitmap_isset(nsec->rr->nsec.types, DNS_TYPE_CNAME) &&
                    !bitmap_isset(nsec->rr->nsec.types, DNS_TYPE_DNAME)) {
                        c->n_hit++;
                        return 1;
                }

                c->n_miss++;
                return 0;
        }

        log_debug("%s cache hit for %s",
                  n > 0    ? "Positive" :
                  nxdomain ? "NXDOMAIN" : "NODATA",
                  dns_resource_key_to_string(key, key_str, sizeof key_str));

        if (n <= 0) {
                c->n_hit++;

                *ret = NULL;
                *rcode = nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SUCCESS;
                *authenticated = have_authenticated && !have_non_authenticated;
                return 1;
        }

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        if (clamp_ttl)
                current = now(clock_boottime_or_monotonic());

        LIST_FOREACH(by_key, j, first) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                if (!j->rr)
                        continue;

                if (clamp_ttl) {
                        rr = dns_resource_record_ref(j->rr);

                        r = dns_resource_record_clamp_ttl(&rr, LESS_BY(j->until, current) / USEC_PER_SEC);
                        if (r < 0)
                                return r;
                }

                r = dns_answer_add(answer, rr ?: j->rr, j->ifindex, j->authenticated ? DNS_ANSWER_AUTHENTICATED : 0);
                if (r < 0)
                        return r;
        }

        c->n_hit++;

        *ret = answer;
        *rcode = DNS_RCODE_SUCCESS;
        *authenticated = have_authenticated && !have_non_authenticated;
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

int dns_cache_export_shared_to_packet(DnsCache *cache, DnsPacket *p) {
        unsigned ancount = 0;
        Iterator iterator;
        DnsCacheItem *i;
        int r;

        assert(cache);
        assert(p);

        HASHMAP_FOREACH(i, cache->by_key, iterator) {
                DnsCacheItem *j;

                LIST_FOREACH(by_key, j, i) {
                        if (!j->rr)
                                continue;

                        if (!j->shared_owner)
                                continue;

                        r = dns_packet_append_rr(p, j->rr, NULL, NULL);
                        if (r == -EMSGSIZE && p->protocol == DNS_PROTOCOL_MDNS) {
                                /* For mDNS, if we're unable to stuff all known answers into the given packet,
                                 * allocate a new one, push the RR into that one and link it to the current one.
                                 */

                                DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);
                                ancount = 0;

                                r = dns_packet_new_query(&p->more, p->protocol, 0, true);
                                if (r < 0)
                                        return r;

                                /* continue with new packet */
                                p = p->more;
                                r = dns_packet_append_rr(p, j->rr, NULL, NULL);
                        }

                        if (r < 0)
                                return r;

                        ancount++;
                }
        }

        DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);

        return 0;
}

void dns_cache_dump(DnsCache *cache, FILE *f) {
        Iterator iterator;
        DnsCacheItem *i;

        if (!cache)
                return;

        if (!f)
                f = stdout;

        HASHMAP_FOREACH(i, cache->by_key, iterator) {
                DnsCacheItem *j;

                LIST_FOREACH(by_key, j, i) {

                        fputc('\t', f);

                        if (j->rr) {
                                const char *t;
                                t = dns_resource_record_to_string(j->rr);
                                if (!t) {
                                        log_oom();
                                        continue;
                                }

                                fputs(t, f);
                                fputc('\n', f);
                        } else {
                                char key_str[DNS_RESOURCE_KEY_STRING_MAX];

                                fputs(dns_resource_key_to_string(j->key, key_str, sizeof key_str), f);
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

unsigned dns_cache_size(DnsCache *cache) {
        if (!cache)
                return 0;

        return hashmap_size(cache->by_key);
}
