/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "format-util.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-packet.h"
#include "string-util.h"

/* Never cache more than 4K entries. RFC 1536, Section 5 suggests to
 * leave DNS caches unbounded, but that's crazy. */
#define CACHE_MAX 4096

/* We never keep any item longer than 2h in our cache unless StaleRetentionSec is greater than zero. */
#define CACHE_TTL_MAX_USEC (2 * USEC_PER_HOUR)

/* The max TTL for stale data is set to 30 seconds. See RFC 8767, Section 6. */
#define CACHE_STALE_TTL_MAX_USEC (30 * USEC_PER_SEC)

/* How long to cache strange rcodes, i.e. rcodes != SUCCESS and != NXDOMAIN (specifically: that's only SERVFAIL for
 * now) */
#define CACHE_TTL_STRANGE_RCODE_USEC (10 * USEC_PER_SEC)

#define CACHEABLE_QUERY_FLAGS (SD_RESOLVED_AUTHENTICATED|SD_RESOLVED_CONFIDENTIAL)

typedef enum DnsCacheItemType DnsCacheItemType;
typedef struct DnsCacheItem DnsCacheItem;

enum DnsCacheItemType {
        DNS_CACHE_POSITIVE,
        DNS_CACHE_NODATA,
        DNS_CACHE_NXDOMAIN,
        DNS_CACHE_RCODE,      /* "strange" RCODE (effective only SERVFAIL for now) */
};

struct DnsCacheItem {
        DnsCacheItemType type;
        int rcode;
        DnsResourceKey *key;     /* The key for this item, i.e. the lookup key */
        DnsResourceRecord *rr;   /* The RR for this item, i.e. the lookup value for positive queries */
        DnsAnswer *answer;       /* The full validated answer, if this is an RRset acquired via a "primary" lookup */
        DnsPacket *full_packet;  /* The full packet this information was acquired with */

        usec_t until;            /* If StaleRetentionSec is greater than zero, until is set to a duration of StaleRetentionSec from the time of TTL expiry. If StaleRetentionSec is zero, both until and until_valid will be set to ttl. */
        usec_t until_valid;      /* The key is for storing the time when the TTL set to expire. */
        uint64_t query_flags;    /* SD_RESOLVED_AUTHENTICATED and/or SD_RESOLVED_CONFIDENTIAL */
        DnssecResult dnssec_result;

        int ifindex;
        int owner_family;
        union in_addr_union owner_address;

        unsigned prioq_idx;
        LIST_FIELDS(DnsCacheItem, by_key);

        bool shared_owner;
};

/* Returns true if this is a cache item created as result of an explicit lookup, or created as "side-effect"
 * of another request. "Primary" entries will carry the full answer data (with NSEC, …) that can aso prove
 * wildcard expansion, non-existence and such, while entries that were created as "side-effect" just contain
 * immediate RR data for the specified RR key, but nothing else. */
#define DNS_CACHE_ITEM_IS_PRIMARY(item) (!!(item)->answer)

static const char *dns_cache_item_type_to_string(DnsCacheItem *item) {
        assert(item);

        switch (item->type) {

        case DNS_CACHE_POSITIVE:
                return "POSITIVE";

        case DNS_CACHE_NODATA:
                return "NODATA";

        case DNS_CACHE_NXDOMAIN:
                return "NXDOMAIN";

        case DNS_CACHE_RCODE:
                return dns_rcode_to_string(item->rcode);
        }

        return NULL;
}

static DnsCacheItem* dns_cache_item_free(DnsCacheItem *i) {
        if (!i)
                return NULL;

        dns_resource_record_unref(i->rr);
        dns_resource_key_unref(i->key);
        dns_answer_unref(i->answer);
        dns_packet_unref(i->full_packet);
        return mfree(i);
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
        DnsCacheItem *first;
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
        DnsCacheItem *first;

        assert(c);
        assert(key);

        first = hashmap_remove(c->by_key, key);
        if (!first)
                return false;

        LIST_FOREACH(by_key, i, first) {
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
                        t = now(CLOCK_BOOTTIME);

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

        return CMP(x->until, y->until);
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
                _unused_ _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;

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
        assert(c);
        assert(rr);

        LIST_FOREACH(by_key, i, (DnsCacheItem*) hashmap_get(c->by_key, rr->key))
                if (i->rr && dns_resource_record_equal(i->rr, rr) > 0)
                        return i;

        return NULL;
}

static usec_t calculate_until_valid(
                DnsResourceRecord *rr,
                uint32_t min_ttl,
                uint32_t nsec_ttl,
                usec_t timestamp,
                bool use_soa_minimum) {

        uint32_t ttl;
        usec_t u;

        assert(rr);

        ttl = MIN(min_ttl, nsec_ttl);
        if (rr->key->type == DNS_TYPE_SOA && use_soa_minimum) {
                /* If this is a SOA RR, and it is requested, clamp to the SOA's minimum field. This is used
                 * when we do negative caching, to determine the TTL for the negative caching entry. See RFC
                 * 2308, Section 5. */

                if (ttl > rr->soa.minimum)
                        ttl = rr->soa.minimum;
        }

        u = ttl * USEC_PER_SEC;
        if (u > CACHE_TTL_MAX_USEC)
                u = CACHE_TTL_MAX_USEC;

        if (rr->expiry != USEC_INFINITY) {
                usec_t left;

                /* Make use of the DNSSEC RRSIG expiry info, if we have it */

                left = LESS_BY(rr->expiry, now(CLOCK_REALTIME));
                if (u > left)
                        u = left;
        }

        return timestamp + u;
}

static usec_t calculate_until(
                usec_t until_valid,
                usec_t stale_retention_usec) {

        return stale_retention_usec > 0 ? usec_add(until_valid, stale_retention_usec) : until_valid;
}

static void dns_cache_item_update_positive(
                DnsCache *c,
                DnsCacheItem *i,
                DnsResourceRecord *rr,
                DnsAnswer *answer,
                DnsPacket *full_packet,
                uint32_t min_ttl,
                uint64_t query_flags,
                bool shared_owner,
                DnssecResult dnssec_result,
                usec_t timestamp,
                int ifindex,
                int owner_family,
                const union in_addr_union *owner_address,
                usec_t stale_retention_usec) {

        assert(c);
        assert(i);
        assert(rr);
        assert(owner_address);

        i->type = DNS_CACHE_POSITIVE;

        if (!i->by_key_prev)
                /* We are the first item in the list, we need to
                 * update the key used in the hashmap */

                assert_se(hashmap_replace(c->by_key, rr->key, i) >= 0);

        DNS_RR_REPLACE(i->rr, dns_resource_record_ref(rr));

        DNS_RESOURCE_KEY_REPLACE(i->key, dns_resource_key_ref(rr->key));

        DNS_ANSWER_REPLACE(i->answer, dns_answer_ref(answer));

        DNS_PACKET_REPLACE(i->full_packet, dns_packet_ref(full_packet));

        i->until_valid = calculate_until_valid(rr, min_ttl, UINT32_MAX, timestamp, false);
        i->until = calculate_until(i->until_valid, stale_retention_usec);
        i->query_flags = query_flags & CACHEABLE_QUERY_FLAGS;
        i->shared_owner = shared_owner;
        i->dnssec_result = dnssec_result;

        i->ifindex = ifindex;

        i->owner_family = owner_family;
        i->owner_address = *owner_address;

        prioq_reshuffle(c->by_expiry, i, &i->prioq_idx);
}

static int dns_cache_put_positive(
                DnsCache *c,
                DnsProtocol protocol,
                DnsResourceRecord *rr,
                DnsAnswer *answer,
                DnsPacket *full_packet,
                uint64_t query_flags,
                bool shared_owner,
                DnssecResult dnssec_result,
                usec_t timestamp,
                int ifindex,
                int owner_family,
                const union in_addr_union *owner_address,
                usec_t stale_retention_usec) {

        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        DnsCacheItem *existing;
        uint32_t min_ttl;
        int r;

        assert(c);
        assert(rr);
        assert(owner_address);

        /* Never cache pseudo RRs */
        if (dns_class_is_pseudo(rr->key->class))
                return 0;
        if (dns_type_is_pseudo(rr->key->type))
                return 0;

        /* Determine the minimal TTL of all RRs in the answer plus the one by the main RR we are supposed to
         * cache. Since we cache whole answers to questions we should never return answers where only some
         * RRs are still valid, hence find the lowest here */
        min_ttl = MIN(dns_answer_min_ttl(answer), rr->ttl);

        /* New TTL is 0? Delete this specific entry... */
        if (min_ttl <= 0) {
                r = dns_cache_remove_by_rr(c, rr);
                log_debug("%s: %s",
                          r > 0 ? "Removed zero TTL entry from cache" : "Not caching zero TTL cache entry",
                          dns_resource_key_to_string(rr->key, key_str, sizeof key_str));
                return 0;
        }

        /* Entry exists already? Update TTL, timestamp and owner */
        existing = dns_cache_get(c, rr);
        if (existing) {
                dns_cache_item_update_positive(
                                c,
                                existing,
                                rr,
                                answer,
                                full_packet,
                                min_ttl,
                                query_flags,
                                shared_owner,
                                dnssec_result,
                                timestamp,
                                ifindex,
                                owner_family,
                                owner_address,
                                stale_retention_usec);
                return 0;
        }

        /* Do not cache mDNS goodbye packet. */
        if (protocol == DNS_PROTOCOL_MDNS && rr->ttl <= 1)
                return 0;

        /* Otherwise, add the new RR */
        r = dns_cache_init(c);
        if (r < 0)
                return r;

        dns_cache_make_space(c, 1);

        _cleanup_(dns_cache_item_freep) DnsCacheItem *i = new(DnsCacheItem, 1);
        if (!i)
                return -ENOMEM;

        /* If StaleRetentionSec is greater than zero, the 'until' property is set to a duration
         * of StaleRetentionSec from the time of TTL expiry.
         * If StaleRetentionSec is zero, both the 'until' and 'until_valid' are set to the TTL duration,
         * leading to the eviction of the record once the TTL expires.*/
        usec_t until_valid = calculate_until_valid(rr, min_ttl, UINT32_MAX, timestamp, false);
        *i = (DnsCacheItem) {
                .type = DNS_CACHE_POSITIVE,
                .key = dns_resource_key_ref(rr->key),
                .rr = dns_resource_record_ref(rr),
                .answer = dns_answer_ref(answer),
                .full_packet = dns_packet_ref(full_packet),
                .until = calculate_until(until_valid, stale_retention_usec),
                .until_valid = until_valid,
                .query_flags = query_flags & CACHEABLE_QUERY_FLAGS,
                .shared_owner = shared_owner,
                .dnssec_result = dnssec_result,
                .ifindex = ifindex,
                .owner_family = owner_family,
                .owner_address = *owner_address,
                .prioq_idx = PRIOQ_IDX_NULL,
        };

        r = dns_cache_link_item(c, i);
        if (r < 0)
                return r;

        log_debug("Added positive %s %s%s cache entry for %s "USEC_FMT"s on %s/%s/%s",
                  FLAGS_SET(i->query_flags, SD_RESOLVED_AUTHENTICATED) ? "authenticated" : "unauthenticated",
                  FLAGS_SET(i->query_flags, SD_RESOLVED_CONFIDENTIAL) ? "confidential" : "non-confidential",
                  i->shared_owner ? " shared" : "",
                  dns_resource_key_to_string(i->key, key_str, sizeof key_str),
                  (i->until - timestamp) / USEC_PER_SEC,
                  i->ifindex == 0 ? "*" : FORMAT_IFNAME(i->ifindex),
                  af_to_name_short(i->owner_family),
                  IN_ADDR_TO_STRING(i->owner_family, &i->owner_address));

        TAKE_PTR(i);
        return 0;
}

static int dns_cache_put_negative(
                DnsCache *c,
                DnsResourceKey *key,
                int rcode,
                DnsAnswer *answer,
                DnsPacket *full_packet,
                uint64_t query_flags,
                DnssecResult dnssec_result,
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
        assert(owner_address);

        /* Never cache pseudo RR keys. DNS_TYPE_ANY is particularly
         * important to filter out as we use this as a pseudo-type for
         * NXDOMAIN entries */
        if (dns_class_is_pseudo(key->class))
                return 0;
        if (dns_type_is_pseudo(key->type))
                return 0;

        if (IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN)) {
                if (!soa)
                        return 0;

                /* For negative replies, check if we have a TTL of a SOA */
                if (nsec_ttl <= 0 || soa->soa.minimum <= 0 || soa->ttl <= 0) {
                        log_debug("Not caching negative entry with zero SOA/NSEC/NSEC3 TTL: %s",
                                  dns_resource_key_to_string(key, key_str, sizeof key_str));
                        return 0;
                }
        } else if (rcode != DNS_RCODE_SERVFAIL)
                return 0;

        r = dns_cache_init(c);
        if (r < 0)
                return r;

        dns_cache_make_space(c, 1);

        i = new(DnsCacheItem, 1);
        if (!i)
                return -ENOMEM;

        *i = (DnsCacheItem) {
                .type =
                        rcode == DNS_RCODE_SUCCESS ? DNS_CACHE_NODATA :
                        rcode == DNS_RCODE_NXDOMAIN ? DNS_CACHE_NXDOMAIN : DNS_CACHE_RCODE,
                .query_flags = query_flags & CACHEABLE_QUERY_FLAGS,
                .dnssec_result = dnssec_result,
                .owner_family = owner_family,
                .owner_address = *owner_address,
                .prioq_idx = PRIOQ_IDX_NULL,
                .rcode = rcode,
                .answer = dns_answer_ref(answer),
                .full_packet = dns_packet_ref(full_packet),
        };

        /* Determine how long to cache this entry. In case we have some RRs in the answer use the lowest TTL
         * of any of them. Typically that's the SOA's TTL, which is OK, but could possibly be lower because
         * of some other RR. Let's better take the lowest option here than a needlessly high one */
        i->until = i->until_valid =
                i->type == DNS_CACHE_RCODE ? timestamp + CACHE_TTL_STRANGE_RCODE_USEC :
                calculate_until_valid(soa, dns_answer_min_ttl(answer), nsec_ttl, timestamp, true);

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
                  dns_cache_item_type_to_string(i),
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
                DnsCacheMode cache_mode,
                DnsProtocol protocol,
                DnsResourceKey *key,
                int rcode,
                DnsAnswer *answer,
                DnsPacket *full_packet,
                uint64_t query_flags,
                DnssecResult dnssec_result,
                uint32_t nsec_ttl,
                int owner_family,
                const union in_addr_union *owner_address,
                usec_t stale_retention_usec) {

        DnsResourceRecord *soa = NULL;
        bool weird_rcode = false;
        DnsAnswerItem *item;
        DnsAnswerFlags flags;
        unsigned cache_keys;
        usec_t timestamp;
        int r;

        assert(c);
        assert(owner_address);

        dns_cache_remove_previous(c, key, answer);

        /* We only care for positive replies and NXDOMAINs, on all other replies we will simply flush the respective
         * entries, and that's it. (Well, with one further exception: since some DNS zones (akamai!) return SERVFAIL
         * consistently for some lookups, and forwarders tend to propagate that we'll cache that too, but only for a
         * short time.) */

        if (IN_SET(rcode, DNS_RCODE_SUCCESS, DNS_RCODE_NXDOMAIN)) {
                if (dns_answer_isempty(answer)) {
                        if (key) {
                                char key_str[DNS_RESOURCE_KEY_STRING_MAX];

                                log_debug("Not caching negative entry without a SOA record: %s",
                                          dns_resource_key_to_string(key, key_str, sizeof key_str));
                        }

                        return 0;
                }

        } else {
                /* Only cache SERVFAIL as "weird" rcode for now. We can add more later, should that turn out to be
                 * beneficial. */
                if (rcode != DNS_RCODE_SERVFAIL)
                        return 0;

                weird_rcode = true;
        }

        cache_keys = dns_answer_size(answer);
        if (key)
                cache_keys++;

        /* Make some space for our new entries */
        dns_cache_make_space(c, cache_keys);

        timestamp = now(CLOCK_BOOTTIME);

        /* Second, add in positive entries for all contained RRs */
        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                int primary = false;

                if (!FLAGS_SET(item->flags, DNS_ANSWER_CACHEABLE) ||
                    !rr_eligible(item->rr))
                        continue;

                if (key) {
                        /* We store the auxiliary RRs and packet data in the cache only if they were in
                         * direct response to the original query. If we cache an RR we also received, and
                         * that is just auxiliary information we can't use the data, hence don't. */

                        primary = dns_resource_key_match_rr(key, item->rr, NULL);
                        if (primary < 0)
                                return primary;
                        if (primary == 0) {
                                primary = dns_resource_key_match_cname_or_dname(key, item->rr->key, NULL);
                                if (primary < 0)
                                        return primary;
                        }
                }

                if (!primary) {
                        DnsCacheItem *first;

                        /* Do not replace existing cache items for primary lookups with non-primary
                         * data. After all the primary lookup data is a lot more useful. */
                        first = hashmap_get(c->by_key, item->rr->key);
                        if (first && DNS_CACHE_ITEM_IS_PRIMARY(first))
                                return 0;
                }

                r = dns_cache_put_positive(
                                c,
                                protocol,
                                item->rr,
                                primary ? answer : NULL,
                                primary ? full_packet : NULL,
                                ((item->flags & DNS_ANSWER_AUTHENTICATED) ? SD_RESOLVED_AUTHENTICATED : 0) |
                                (query_flags & SD_RESOLVED_CONFIDENTIAL),
                                item->flags & DNS_ANSWER_SHARED_OWNER,
                                dnssec_result,
                                timestamp,
                                item->ifindex,
                                owner_family,
                                owner_address,
                                stale_retention_usec);
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

        /* But not if it has a matching CNAME/DNAME (the negative caching will be done on the canonical name,
         * not on the alias) */
        r = dns_answer_find_cname_or_dname(answer, key, NULL, NULL);
        if (r < 0)
                goto fail;
        if (r > 0)
                return 0;

        /* See https://tools.ietf.org/html/rfc2308, which say that a matching SOA record in the packet is used to
         * enable negative caching. We apply one exception though: if we are about to cache a weird rcode we do so
         * regardless of a SOA. */
        r = dns_answer_find_soa(answer, key, &soa, &flags);
        if (r < 0)
                goto fail;
        if (r == 0 && !weird_rcode)
                return 0;
        if (r > 0) {
                /* Refuse using the SOA data if it is unsigned, but the key is signed */
                if (FLAGS_SET(query_flags, SD_RESOLVED_AUTHENTICATED) &&
                    (flags & DNS_ANSWER_AUTHENTICATED) == 0)
                        return 0;
        }

        if (cache_mode == DNS_CACHE_MODE_NO_NEGATIVE) {
                char key_str[DNS_RESOURCE_KEY_STRING_MAX];
                log_debug("Not caching negative entry for: %s, cache mode set to no-negative",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
                return 0;
        }

        r = dns_cache_put_negative(
                        c,
                        key,
                        rcode,
                        answer,
                        full_packet,
                        query_flags,
                        dnssec_result,
                        nsec_ttl,
                        timestamp,
                        soa,
                        owner_family,
                        owner_address);
        if (r < 0)
                goto fail;

        return 0;

fail:
        /* Adding all RRs failed. Let's clean up what we already
         * added, just in case */

        if (key)
                dns_cache_remove_by_key(c, key);

        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                if ((item->flags & DNS_ANSWER_CACHEABLE) == 0)
                        continue;

                dns_cache_remove_by_key(c, item->rr->key);
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
                if (i && i->type != DNS_CACHE_NODATA)
                        return i;

                /* OK, let's look for cached DNAME records. */
                for (;;) {
                        if (isempty(n))
                                return NULL;

                        i = hashmap_get(c->by_key, &DNS_RESOURCE_KEY_CONST(k->class, DNS_TYPE_DNAME, n));
                        if (i && i->type != DNS_CACHE_NODATA)
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

static int answer_add_clamp_ttl(
                DnsAnswer **answer,
                DnsResourceRecord *rr,
                int ifindex,
                DnsAnswerFlags answer_flags,
                DnsResourceRecord *rrsig,
                uint64_t query_flags,
                usec_t until,
                usec_t current) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *patched = NULL, *patched_rrsig = NULL;
        int r;

        assert(answer);
        assert(rr);

        if (FLAGS_SET(query_flags, SD_RESOLVED_CLAMP_TTL)) {
                uint32_t left_ttl;

                assert(current > 0);

                /* Let's determine how much time is left for this cache entry. Note that we round down, but
                 * clamp this to be 1s at minimum, since we usually want records to remain cached better too
                 * short a time than too long a time, but otoh don't want to return 0 ever, since that has
                 * special semantics in various contexts — in particular in mDNS */

                left_ttl = MAX(1U, LESS_BY(until, current) / USEC_PER_SEC);

                patched = dns_resource_record_ref(rr);

                r = dns_resource_record_clamp_ttl(&patched, left_ttl);
                if (r < 0)
                        return r;

                rr = patched;

                if (rrsig) {
                        patched_rrsig = dns_resource_record_ref(rrsig);
                        r = dns_resource_record_clamp_ttl(&patched_rrsig, left_ttl);
                        if (r < 0)
                                return r;

                        rrsig = patched_rrsig;
                }
        }

        rr->until = until;
        r = dns_answer_add_extend(answer, rr, ifindex, answer_flags, rrsig);
        if (r < 0)
                return r;

        return 0;
}

int dns_cache_lookup(
                DnsCache *c,
                DnsResourceKey *key,
                uint64_t query_flags,
                int *ret_rcode,
                DnsAnswer **ret_answer,
                DnsPacket **ret_full_packet,
                uint64_t *ret_query_flags,
                DnssecResult *ret_dnssec_result) {

        _cleanup_(dns_packet_unrefp) DnsPacket *full_packet = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        unsigned n = 0;
        int r;
        bool nxdomain = false;
        DnsCacheItem *first, *nsec = NULL;
        bool have_authenticated = false, have_non_authenticated = false, have_confidential = false, have_non_confidential = false;
        usec_t current = 0;
        int found_rcode = -1;
        DnssecResult dnssec_result = -1;
        int have_dnssec_result = -1;

        assert(c);
        assert(key);

        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                /* If we have ANY lookups we don't use the cache, so that the caller refreshes via the
                 * network. */

                log_debug("Ignoring cache for ANY lookup: %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
                goto miss;
        }

        first = dns_cache_get_by_key_follow_cname_dname_nsec(c, key);
        if (!first) {
                /* If one question cannot be answered we need to refresh */

                log_debug("Cache miss for %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));
                goto miss;
        }

        if ((query_flags & (SD_RESOLVED_CLAMP_TTL | SD_RESOLVED_NO_STALE)) != 0) {
                /* 'current' is always passed to answer_add_clamp_ttl(), but is only used conditionally.
                 * We'll do the same assert there to make sure that it was initialized properly.
                 * 'current' is also used below when SD_RESOLVED_NO_STALE is set. */
                current = now(CLOCK_BOOTTIME);
                assert(current > 0);
        }

        LIST_FOREACH(by_key, j, first) {
                /* If the caller doesn't allow us to answer questions from cache data learned from
                 * "side-effect", skip this entry. */
                if (FLAGS_SET(query_flags, SD_RESOLVED_REQUIRE_PRIMARY) &&
                    !DNS_CACHE_ITEM_IS_PRIMARY(j)) {
                        log_debug("Primary answer was requested for cache lookup for %s, which we don't have.",
                                  dns_resource_key_to_string(key, key_str, sizeof key_str));

                        goto miss;
                }

                /* Skip the next part if ttl is expired and requested with no stale flag. */
                if (FLAGS_SET(query_flags, SD_RESOLVED_NO_STALE) && j->until_valid < current) {
                        log_debug("Requested with no stale and TTL expired for %s",
                                                dns_resource_key_to_string(key, key_str, sizeof key_str));

                        goto miss;
                }

                if (j->type == DNS_CACHE_NXDOMAIN)
                        nxdomain = true;
                else if (j->type == DNS_CACHE_RCODE)
                        found_rcode = j->rcode;
                else if (j->rr) {
                        if (j->rr->key->type == DNS_TYPE_NSEC)
                                nsec = j;

                        n++;
                }

                if (FLAGS_SET(j->query_flags, SD_RESOLVED_AUTHENTICATED))
                        have_authenticated = true;
                else
                        have_non_authenticated = true;

                if (FLAGS_SET(j->query_flags, SD_RESOLVED_CONFIDENTIAL))
                        have_confidential = true;
                else
                        have_non_confidential = true;

                if (j->dnssec_result < 0) {
                        have_dnssec_result = false; /* an entry without dnssec result? then invalidate things for good */
                        dnssec_result = _DNSSEC_RESULT_INVALID;
                } else if (have_dnssec_result < 0) {
                        have_dnssec_result = true; /* So far no result seen, let's pick this one up */
                        dnssec_result = j->dnssec_result;
                } else if (have_dnssec_result > 0 && j->dnssec_result != dnssec_result) {
                        have_dnssec_result = false; /* conflicting result seen? then invalidate for good */
                        dnssec_result = _DNSSEC_RESULT_INVALID;
                }

                /* If the question is being resolved using stale data, the clamp TTL will be set to CACHE_STALE_TTL_MAX_USEC. */
                usec_t until = FLAGS_SET(query_flags, SD_RESOLVED_NO_STALE) ? j->until_valid
                                                                            : usec_add(current, CACHE_STALE_TTL_MAX_USEC);

                /* Append the answer RRs to our answer. Ideally we have the answer object, which we
                 * preferably use. But if the cached entry was generated as "side-effect" of a reply,
                 * i.e. from validated auxiliary records rather than from the main reply, then we use the
                 * individual RRs only instead. */
                if (j->answer) {

                        /* Minor optimization, if the full answer object of this and the previous RR is the
                         * same, don't bother adding it again. Typically we store a full RRset here, hence
                         * that should be the case. */
                        if (!j->by_key_prev || j->answer != j->by_key_prev->answer) {
                                DnsAnswerItem *item;

                                DNS_ANSWER_FOREACH_ITEM(item, j->answer) {
                                        r = answer_add_clamp_ttl(
                                                        &answer,
                                                        item->rr,
                                                        item->ifindex,
                                                        item->flags,
                                                        item->rrsig,
                                                        query_flags,
                                                        until,
                                                        current);
                                        if (r < 0)
                                                return r;
                                }
                        }

                } else if (j->rr) {
                        r = answer_add_clamp_ttl(
                                        &answer,
                                        j->rr,
                                        j->ifindex,
                                        FLAGS_SET(j->query_flags, SD_RESOLVED_AUTHENTICATED) ? DNS_ANSWER_AUTHENTICATED : 0,
                                        NULL,
                                        query_flags,
                                        until,
                                        current);
                        if (r < 0)
                                return r;
                }

                /* We'll return any packet we have for this. Typically all cache entries for the same key
                 * should come from the same packet anyway, hence it doesn't really matter which packet we
                 * return here, they should all resolve to the same anyway. */
                if (!full_packet && j->full_packet)
                        full_packet = dns_packet_ref(j->full_packet);
        }

        if (found_rcode >= 0) {
                log_debug("RCODE %s cache hit for %s",
                          FORMAT_DNS_RCODE(found_rcode),
                          dns_resource_key_to_string(key, key_str, sizeof(key_str)));

                if (ret_rcode)
                        *ret_rcode = found_rcode;
                if (ret_answer)
                        *ret_answer = TAKE_PTR(answer);
                if (ret_full_packet)
                        *ret_full_packet = TAKE_PTR(full_packet);
                if (ret_query_flags)
                        *ret_query_flags = 0;
                if (ret_dnssec_result)
                        *ret_dnssec_result = dnssec_result;

                c->n_hit++;
                return 1;
        }

        if (nsec && !IN_SET(key->type, DNS_TYPE_NSEC, DNS_TYPE_DS)) {
                /* Note that we won't derive information for DS RRs from an NSEC, because we only cache NSEC
                 * RRs from the lower-zone of a zone cut, but the DS RRs are on the upper zone. */

                log_debug("NSEC NODATA cache hit for %s",
                          dns_resource_key_to_string(key, key_str, sizeof key_str));

                /* We only found an NSEC record that matches our name.  If it says the type doesn't exist
                 * report NODATA. Otherwise report a cache miss. */

                if (ret_rcode)
                        *ret_rcode = DNS_RCODE_SUCCESS;
                if (ret_answer)
                        *ret_answer = TAKE_PTR(answer);
                if (ret_full_packet)
                        *ret_full_packet = TAKE_PTR(full_packet);
                if (ret_query_flags)
                        *ret_query_flags = nsec->query_flags;
                if (ret_dnssec_result)
                        *ret_dnssec_result = nsec->dnssec_result;

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

                if (ret_rcode)
                        *ret_rcode = nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_SUCCESS;
                if (ret_answer)
                        *ret_answer = TAKE_PTR(answer);
                if (ret_full_packet)
                        *ret_full_packet = TAKE_PTR(full_packet);
                if (ret_query_flags)
                        *ret_query_flags =
                                ((have_authenticated && !have_non_authenticated) ? SD_RESOLVED_AUTHENTICATED : 0) |
                                ((have_confidential && !have_non_confidential) ? SD_RESOLVED_CONFIDENTIAL : 0);
                if (ret_dnssec_result)
                        *ret_dnssec_result = dnssec_result;

                return 1;
        }

        c->n_hit++;

        if (ret_rcode)
                *ret_rcode = DNS_RCODE_SUCCESS;
        if (ret_answer)
                *ret_answer = TAKE_PTR(answer);
        if (ret_full_packet)
                *ret_full_packet = TAKE_PTR(full_packet);
        if (ret_query_flags)
                *ret_query_flags =
                        ((have_authenticated && !have_non_authenticated) ? SD_RESOLVED_AUTHENTICATED : 0) |
                        ((have_confidential && !have_non_confidential) ? SD_RESOLVED_CONFIDENTIAL : 0);
        if (ret_dnssec_result)
                *ret_dnssec_result = dnssec_result;

        return n;

miss:
        if (ret_rcode)
                *ret_rcode = DNS_RCODE_SUCCESS;
        if (ret_answer)
                *ret_answer = NULL;
        if (ret_full_packet)
                *ret_full_packet = NULL;
        if (ret_query_flags)
                *ret_query_flags = 0;
        if (ret_dnssec_result)
                *ret_dnssec_result = _DNSSEC_RESULT_INVALID;

        c->n_miss++;
        return 0;
}

int dns_cache_check_conflicts(DnsCache *cache, DnsResourceRecord *rr, int owner_family, const union in_addr_union *owner_address) {
        DnsCacheItem *first;
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

int dns_cache_export_shared_to_packet(DnsCache *cache, DnsPacket *p, usec_t ts, unsigned max_rr) {
        unsigned ancount = 0;
        DnsCacheItem *i;
        int r;

        assert(cache);
        assert(p);
        assert(p->protocol == DNS_PROTOCOL_MDNS);

        HASHMAP_FOREACH(i, cache->by_key)
                LIST_FOREACH(by_key, j, i) {
                        if (!j->rr)
                                continue;

                        if (!j->shared_owner)
                                continue;

                        /* RFC6762 7.1: Don't append records with less than half the TTL remaining
                         * as known answers. */
                        if (usec_sub_unsigned(j->until, ts) < j->rr->ttl * USEC_PER_SEC / 2)
                                continue;

                        if (max_rr > 0 && ancount >= max_rr) {
                                DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);
                                ancount = 0;

                                r = dns_packet_new_query(&p->more, p->protocol, 0, true);
                                if (r < 0)
                                        return r;

                                p = p->more;

                                max_rr = UINT_MAX;
                        }

                        r = dns_packet_append_rr(p, j->rr, 0, NULL, NULL);
                        if (r == -EMSGSIZE) {
                                if (max_rr == 0)
                                        /* If max_rr == 0, do not allocate more packets. */
                                        goto finalize;

                                /* If we're unable to stuff all known answers into the given packet, allocate
                                 * a new one, push the RR into that one and link it to the current one. */

                                DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);
                                ancount = 0;

                                r = dns_packet_new_query(&p->more, p->protocol, 0, true);
                                if (r < 0)
                                        return r;

                                /* continue with new packet */
                                p = p->more;
                                r = dns_packet_append_rr(p, j->rr, 0, NULL, NULL);
                        }

                        if (r < 0)
                                return r;

                        ancount++;
                }

finalize:
        DNS_PACKET_HEADER(p)->ancount = htobe16(ancount);

        return 0;
}

void dns_cache_dump(DnsCache *cache, FILE *f) {
        DnsCacheItem *i;

        if (!cache)
                return;

        if (!f)
                f = stdout;

        HASHMAP_FOREACH(i, cache->by_key)
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
                                fputs(dns_cache_item_type_to_string(j), f);
                                fputc('\n', f);
                        }
                }
}

int dns_cache_dump_to_json(DnsCache *cache, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *c = NULL;
        DnsCacheItem *i;
        int r;

        assert(cache);
        assert(ret);

        HASHMAP_FOREACH(i, cache->by_key) {
                _cleanup_(json_variant_unrefp) JsonVariant *d = NULL, *k = NULL;

                r = dns_resource_key_to_json(i->key, &k);
                if (r < 0)
                        return r;

                if (i->rr) {
                        _cleanup_(json_variant_unrefp) JsonVariant *l = NULL;

                        LIST_FOREACH(by_key, j, i) {
                                _cleanup_(json_variant_unrefp) JsonVariant *rj = NULL;

                                assert(j->rr);

                                r = dns_resource_record_to_json(j->rr, &rj);
                                if (r < 0)
                                        return r;

                                r = dns_resource_record_to_wire_format(j->rr, /* canonical= */ false); /* don't use DNSSEC canonical format, since it removes casing, but we want that for DNS_SD compat */
                                if (r < 0)
                                        return r;

                                r = json_variant_append_arrayb(
                                                &l,
                                                JSON_BUILD_OBJECT(
                                                                JSON_BUILD_PAIR_VARIANT("rr", rj),
                                                                JSON_BUILD_PAIR_BASE64("raw", j->rr->wire_format, j->rr->wire_format_size)));
                                if (r < 0)
                                        return r;
                        }

                        if (!l) {
                                r = json_variant_new_array(&l, NULL, 0);
                                if (r < 0)
                                        return r;
                        }

                        r = json_build(&d,
                                       JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR_VARIANT("key", k),
                                                       JSON_BUILD_PAIR_VARIANT("rrs", l),
                                                       JSON_BUILD_PAIR_UNSIGNED("until", i->until)));
                } else if (i->type == DNS_CACHE_NODATA) {
                        r = json_build(&d,
                                       JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR_VARIANT("key", k),
                                                       JSON_BUILD_PAIR_EMPTY_ARRAY("rrs"),
                                                       JSON_BUILD_PAIR_UNSIGNED("until", i->until)));
                } else
                        r = json_build(&d,
                                       JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR_VARIANT("key", k),
                                                       JSON_BUILD_PAIR_STRING("type", dns_cache_item_type_to_string(i)),
                                                       JSON_BUILD_PAIR_UNSIGNED("until", i->until)));
                if (r < 0)
                        return r;

                r = json_variant_append_array(&c, d);
                if (r < 0)
                        return r;
        }

        if (!c)
                return json_variant_new_array(ret, NULL, 0);

        *ret = TAKE_PTR(c);
        return 0;
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
