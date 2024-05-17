/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dns-type.h"
#include "resolve-util.h"
#include "resolved-def.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

static DnsCache new_cache(void) {
        return (DnsCache) {};
}

typedef struct PutArgs {
        DnsCacheMode cache_mode;
        DnsProtocol protocol;
        DnsResourceKey *key;
        int rcode;
        DnsAnswer *answer;
        DnsPacket *full_packet;
        uint64_t query_flags;
        DnssecResult dnssec_result;
        uint32_t nsec_ttl;
        int owner_family;
        const union in_addr_union owner_address;
        usec_t stale_retention_usec;
} PutArgs;

static PutArgs mk_put_args(void) {
        return (PutArgs) {
                .cache_mode = DNS_CACHE_MODE_YES,
                .protocol = DNS_PROTOCOL_DNS,
                .key = NULL,
                .rcode = DNS_RCODE_SUCCESS,
                .answer = NULL,
                .full_packet = NULL,
                .query_flags = SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL,
                .dnssec_result = DNSSEC_UNSIGNED,
                .nsec_ttl = 3600,
                .owner_family = AF_INET,
                .owner_address = { .in.s_addr = htobe32(0x01020304) },
                .stale_retention_usec = 0
        };
}

static int cache_put(DnsCache *cache, PutArgs *args) {
        return dns_cache_put(cache,
                args->cache_mode,
                args->protocol,
                args->key,
                args->rcode,
                args->answer,
                args->full_packet,
                args->query_flags,
                args->dnssec_result,
                args->nsec_ttl,
                args->owner_family,
                &args->owner_address,
                args->stale_retention_usec);
}

static void dns_cache_unrefp(DnsCache *cache) {
        dns_cache_flush(cache);
}

static void put_args_unrefp(PutArgs *args) {
        dns_resource_key_unref(args->key);
        dns_answer_unref(args->answer);
        dns_packet_unref(args->full_packet);
}

TEST(dns_a_success_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        put_args.rcode = DNS_RCODE_SUCCESS;

        put_args.answer = dns_answer_new(1);

        rr = dns_resource_record_new(put_args.key);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        rr->ttl = 3600;
        flags = DNS_ANSWER_CACHEABLE;
        dns_answer_add(put_args.answer, rr, 1, flags, NULL);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_zero_ttl_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        put_args.rcode = DNS_RCODE_SUCCESS;

        put_args.answer = dns_answer_new(1);

        rr = dns_resource_record_new(put_args.key);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        rr->ttl = 0;
        flags = DNS_ANSWER_CACHEABLE;
        dns_answer_add(put_args.answer, rr, 1, flags, NULL);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_not_cacheable_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        put_args.rcode = DNS_RCODE_SUCCESS;

        put_args.answer = dns_answer_new(1);

        rr = dns_resource_record_new(put_args.key);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        rr->ttl = 3600;
        flags = 0;
        dns_answer_add(put_args.answer, rr, 1, flags, NULL);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
