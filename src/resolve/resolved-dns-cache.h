/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"
#include "list.h"
#include "prioq.h"
#include "resolve-util.h"
#include "resolved-dns-dnssec.h"
#include "time-util.h"

typedef struct DnsCache {
        Hashmap *by_key;
        Prioq *by_expiry;
        unsigned n_hit;
        unsigned n_miss;
} DnsCache;

#include "resolved-dns-answer.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"

void dns_cache_flush(DnsCache *c);
void dns_cache_prune(DnsCache *c);

int dns_cache_put(
                DnsCache *c,
                DnsCacheMode cache_mode,
                DnsResourceKey *key,
                int rcode,
                DnsAnswer *answer,
                DnsPacket *full_packet,
                uint64_t query_flags,
                DnssecResult dnssec_result,
                uint32_t nsec_ttl,
                int owner_family,
                const union in_addr_union *owner_address);

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
bool dns_cache_is_empty(DnsCache *cache);

unsigned dns_cache_size(DnsCache *cache);

int dns_cache_export_shared_to_packet(DnsCache *cache, DnsPacket *p, usec_t ts, unsigned max_rr);
