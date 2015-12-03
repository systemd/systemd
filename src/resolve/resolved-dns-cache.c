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

#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-packet.h"
#include "string-util.h"

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
        bool authenticated;
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

static void dns_cache_item_update_positive(DnsCache *c, DnsCacheItem *i, DnsResourceRecord *rr, bool authenticated, usec_t timestamp) {
        assert(c);
        assert(i);
        assert(rr);

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

        i->authenticated = authenticated;
        i->until = timestamp + MIN(rr->ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);

        prioq_reshuffle(c->by_expiry, i, &i->prioq_idx);
}

static int dns_cache_put_positive(
                DnsCache *c,
                DnsResourceRecord *rr,
                bool authenticated,
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
                r = dns_resource_key_to_string(rr->key, &key_str);
                if (r < 0)
                        return r;

                if (dns_cache_remove(c, rr->key))
                        log_debug("Removed zero TTL entry from cache: %s", key_str);
                else
                        log_debug("Not caching zero TTL cache entry: %s", key_str);

                return 0;
        }

        if (rr->key->class == DNS_CLASS_ANY)
                return 0;
        if (rr->key->type == DNS_TYPE_ANY)
                return 0;

        /* Entry exists already? Update TTL and timestamp */
        existing = dns_cache_get(c, rr);
        if (existing) {
                dns_cache_item_update_positive(c, existing, rr, authenticated, timestamp);
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
        i->authenticated = authenticated;

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
                bool authenticated,
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
                /* This is particularly important to filter out as we use this as a
                 * pseudo-type for NXDOMAIN entries */
                return 0;
        if (soa_ttl <= 0) {
                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Not caching negative entry with zero SOA TTL: %s", key_str);

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
        i->until = timestamp + MIN(soa_ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);
        i->prioq_idx = PRIOQ_IDX_NULL;
        i->owner_family = owner_family;
        i->owner_address = *owner_address;
        i->authenticated = authenticated;

        if (i->type == DNS_CACHE_NXDOMAIN) {
                /* NXDOMAIN entries should apply equally to all types, so we use ANY as
                 * a pseudo type for this purpose here. */
                i->key = dns_resource_key_new(key->class, DNS_TYPE_ANY, DNS_RESOURCE_KEY_NAME(key));
                if (!i->key)
                        return -ENOMEM;
        } else
                i->key = dns_resource_key_ref(key);

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
                DnsResourceKey *key,
                int rcode,
                DnsAnswer *answer,
                unsigned max_rrs,
                bool authenticated,
                usec_t timestamp,
                int owner_family,
                const union in_addr_union *owner_address) {

        DnsResourceRecord *soa = NULL;
        unsigned cache_keys, i;
        int r;

        assert(c);

        if (key) {
                /* First, if we were passed a key, delete all matching old RRs,
                 * so that we only keep complete by_key in place. */
                dns_cache_remove(c, key);
        }

        if (!answer) {
                _cleanup_free_ char *key_str = NULL;

                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Not caching negative entry without a SOA record: %s", key_str);

                return 0;
        }

        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->items[i].rr->key);

        /* We only care for positive replies and NXDOMAINs, on all
         * other replies we will simply flush the respective entries,
         * and that's it */

        if (!IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN))
                return 0;

        cache_keys = answer->n_rrs;

        if (key)
                cache_keys ++;

        /* Make some space for our new entries */
        dns_cache_make_space(c, cache_keys);

        if (timestamp <= 0)
                timestamp = now(clock_boottime_or_monotonic());

        /* Second, add in positive entries for all contained RRs */
        for (i = 0; i < MIN(max_rrs, answer->n_rrs); i++) {
                DnsResourceRecord *rr = answer->items[i].rr;

                if (rr->key->cache_flush)
                        dns_cache_remove(c, rr->key);

                r = dns_cache_put_positive(c, rr, authenticated, timestamp, owner_family, owner_address);
                if (r < 0)
                        goto fail;
        }

        if (!key)
                return 0;

        /* Third, add in negative entries if the key has no RR */
        r = dns_answer_match_key(answer, key);
        if (r < 0)
                goto fail;
        if (r > 0)
                return 0;

        /* But not if it has a matching CNAME/DNAME (the negative
         * caching will be done on the canonical name, not on the
         * alias) */
        r = dns_answer_find_cname_or_dname(answer, key, NULL);
        if (r < 0)
                goto fail;
        if (r > 0)
                return 0;

        /* See https://tools.ietf.org/html/rfc2308, which say that a
         * matching SOA record in the packet is used to to enable
         * negative caching. */

        r = dns_answer_find_soa(answer, key, &soa);
        if (r < 0)
                goto fail;
        if (r == 0)
                return 0;

        r = dns_cache_put_negative(c, key, rcode, authenticated, timestamp, MIN(soa->soa.minimum, soa->ttl), owner_family, owner_address);
        if (r < 0)
                goto fail;

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        if (key)
                dns_cache_remove(c, key);

        for (i = 0; i < answer->n_rrs; i++)
                dns_cache_remove(c, answer->items[i].rr->key);

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

        n = DNS_RESOURCE_KEY_NAME(k);

        /* Check if we have an NXDOMAIN cache item for the name, notice that we use
         * the pseudo-type ANY for NXDOMAIN cache items. */
        i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_ANY, n));
        if (i && i->type == DNS_CACHE_NXDOMAIN)
                return i;

        /* The following record types should never be redirected. See
         * <https://tools.ietf.org/html/rfc4035#section-2.5>. */
        if (!IN_SET(k->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME,
                            DNS_TYPE_NSEC3, DNS_TYPE_NSEC, DNS_TYPE_RRSIG,
                            DNS_TYPE_NXT, DNS_TYPE_SIG, DNS_TYPE_KEY)) {
                /* Check if we have a CNAME record instead */
                i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_CNAME, n));
                if (i)
                        return i;

                /* OK, let's look for cached DNAME records. */
                for (;;) {
                        char label[DNS_LABEL_MAX];

                        if (isempty(n))
                                return NULL;

                        i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_DNAME, n));
                        if (i)
                                return i;

                        /* Jump one label ahead */
                        r = dns_label_unescape(&n, label, sizeof(label));
                        if (r <= 0)
                                return NULL;
                }
        }

        if (k-> type != DNS_TYPE_NSEC) {
                /* Check if we have an NSEC record instead for the name. */
                i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_NSEC, n));
                if (i)
                        return i;
        }

        return NULL;
}

int dns_cache_lookup(DnsCache *c, DnsResourceKey *key, int *rcode, DnsAnswer **ret, bool *authenticated) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned n = 0;
        int r;
        bool nxdomain = false;
        _cleanup_free_ char *key_str = NULL;
        DnsCacheItem *j, *first, *nsec = NULL;
        bool have_authenticated = false, have_non_authenticated = false;

        assert(c);
        assert(key);
        assert(rcode);
        assert(ret);
        assert(authenticated);

        if (key->type == DNS_TYPE_ANY ||
            key->class == DNS_CLASS_ANY) {

                /* If we have ANY lookups we don't use the cache, so
                 * that the caller refreshes via the network. */

                r = dns_resource_key_to_string(key, &key_str);
                if (r < 0)
                        return r;

                log_debug("Ignoring cache for ANY lookup: %s", key_str);

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                return 0;
        }

        first = dns_cache_get_by_key_follow_cname_dname_nsec(c, key);
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

        r = dns_resource_key_to_string(key, &key_str);
        if (r < 0)
                return r;

        if (nsec && key->type != DNS_TYPE_NSEC) {
                log_debug("NSEC NODATA cache hit for %s", key_str);

                /* We only found an NSEC record that matches our name.
                 * If it says the type doesn't exit report
                 * NODATA. Otherwise report a cache miss. */

                *ret = NULL;
                *rcode = DNS_RCODE_SUCCESS;
                *authenticated = nsec->authenticated;

                return !bitmap_isset(nsec->rr->nsec.types, key->type) &&
                       !bitmap_isset(nsec->rr->nsec.types, DNS_TYPE_CNAME) &&
                       !bitmap_isset(nsec->rr->nsec.types, DNS_TYPE_DNAME);
        }

        log_debug("%s cache hit for %s",
                  n > 0    ? "Positive" :
                  nxdomain ? "NXDOMAIN" : "NODATA",
                  key_str);

        if (n <= 0) {
                *ret = NULL;
                *rcode = nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SUCCESS;
                *authenticated = have_authenticated && !have_non_authenticated;
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
                        _cleanup_free_ char *t = NULL;

                        if (!j->rr)
                                continue;

                        if (!dns_key_is_shared(j->rr->key))
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

                        ancount ++;
                }
        }

        DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);

        return 0;
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
