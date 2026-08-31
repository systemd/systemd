/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

/* Never cache more than 4K entries by default. RFC 1536, Section 5 suggests to
 * leave DNS caches unbounded, but that's crazy. */
#define DEFAULT_CACHE_MAX 4096U
#define CACHE_MAX_UPPER_LIMIT (1U << 24)

/* The max TTL for stale data is set to 30 seconds. See RFC 8767, Section 6. */
#define CACHE_STALE_TTL_MAX_USEC (30 * USEC_PER_SEC)

typedef struct DnsCache {
        Hashmap *by_key;
        Prioq *by_expiry;
        unsigned n_hit;
        unsigned n_miss;
        unsigned cache_max;
} DnsCache;

void dns_cache_flush(DnsCache *c);
void dns_cache_prune(DnsCache *c);

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
                usec_t stale_retention_usec);

int dns_cache_lookup(
                DnsCache *c,
                DnsResourceKey *key,
                uint64_t query_flags,
                int *ret_rcode,
                DnsAnswer **ret_answer,
                DnsPacket **ret_full_packet,
                uint64_t *ret_query_flags,
                DnssecResult *ret_dnssec_result);

int dns_cache_check_conflicts(DnsCache *cache, DnsResourceRecord *rr, int owner_family, const union in_addr_union *owner_address);

void dns_cache_dump(DnsCache *cache, FILE *f);
int dns_cache_dump_to_json(DnsCache *cache, sd_json_variant **ret);

bool dns_cache_is_empty(DnsCache *cache);

unsigned dns_cache_size(DnsCache *cache);

int dns_cache_export_shared_to_packet(DnsCache *cache, DnsPacket *p, usec_t ts, unsigned max_rr);

/* Eviction time (DnsCacheItem.until) of the earliest-expiring entry, USEC_INFINITY for an empty
 * cache. Not the TTL expiry: with StaleRetentionSec= set the two differ by that window, and it is
 * until_valid that governs whether a lookup may still serve the entry. */
usec_t dns_cache_next_expiry(DnsCache *c);
