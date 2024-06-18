/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "dns-type.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "resolve-util.h"
#include "resolved-def.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"
#include "tests.h"
#include "tmpfile-util.h"

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
        PutArgs put_args = {
                .cache_mode = DNS_CACHE_MODE_YES,
                .protocol = DNS_PROTOCOL_DNS,
                .key = NULL,
                .rcode = DNS_RCODE_SUCCESS,
                .answer = dns_answer_new(0),
                .full_packet = NULL,
                .query_flags = SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL,
                .dnssec_result = DNSSEC_UNSIGNED,
                .nsec_ttl = 3600,
                .owner_family = AF_INET,
                .owner_address = { .in.s_addr = htobe32(0x01020304) },
                .stale_retention_usec = 0
        };

        ASSERT_NOT_NULL(put_args.answer);
        return put_args;
}

static int cache_put(DnsCache *cache, PutArgs *args) {
        ASSERT_NOT_NULL(cache);
        ASSERT_NOT_NULL(args);

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
        ASSERT_NOT_NULL(args);

        dns_resource_key_unref(args->key);
        dns_answer_unref(args->answer);
        dns_packet_unref(args->full_packet);
}

static void answer_add_a(PutArgs *args, DnsResourceKey *key, int addr, int ttl, DnsAnswerFlags flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new(key);
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(addr);
        rr->ttl = ttl;
        dns_answer_add(args->answer, rr, 1, flags, NULL);
}

static void answer_add_cname(PutArgs *args, DnsResourceKey *key, const char *alias, int ttl, DnsAnswerFlags flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new(key);
        ASSERT_NOT_NULL(rr);
        rr->cname.name = strdup(alias);
        rr->ttl = ttl;
        dns_answer_add(args->answer, rr, 1, flags, NULL);
}

#define BY_IDX(json, idx) sd_json_variant_by_index(json, idx)
#define BY_KEY(json, key) sd_json_variant_by_key(json, key)
#define INTVAL(json) sd_json_variant_integer(json)
#define STRVAL(json) sd_json_variant_string(json)

/* ================================================================
 * dns_cache_put()
 * ================================================================ */

TEST(dns_a_success_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_non_matching_type_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_non_matching_name_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_escaped_key_returns_error) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_ERROR(cache_put(&cache, &put_args), EINVAL);
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_empty_answer_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_nxdomain_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;
        dns_answer_add_soa(put_args.answer, "example.com", 3600, 0);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_servfail_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SERVFAIL;

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_refused_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_REFUSED;

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_zero_ttl_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 0, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_zero_ttl_removes_existing_entry) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));

        dns_answer_unref(put_args.answer);
        put_args.answer = dns_answer_new(1);
        ASSERT_NOT_NULL(put_args.answer);
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 0, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_not_cacheable_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, 0);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_to_cname_success_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_cname(&put_args, key, "example.com", 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_to_cname_success_escaped_name_returns_error) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.\\example.com");
        ASSERT_NOT_NULL(key);
        answer_add_cname(&put_args, key, "example.com", 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_ERROR(cache_put(&cache, &put_args), EINVAL);
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

/* ================================================================
 * dns_cache_lookup()
 * ================================================================ */

TEST(dns_cache_lookup_miss) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_FALSE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 0u);
        ASSERT_EQ(cache.n_miss, 1u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, 0u);

        ASSERT_EQ(dns_answer_size(ret_answer), 0u);
}

TEST(dns_cache_lookup_success) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_TRUE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, SD_RESOLVED_CONFIDENTIAL);

        ASSERT_EQ(dns_answer_size(ret_answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
}

TEST(dns_cache_lookup_returns_most_recent_response) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        args1.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(args1.key);
        args1.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&args1, args1.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &args1);

        args2.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(args2.key);
        args2.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&args2, args2.key, 0x7f01a8c0, 2400, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &args2);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_TRUE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, SD_RESOLVED_CONFIDENTIAL);

        ASSERT_EQ(dns_answer_size(ret_answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f01a8c0);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_FALSE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);
}

TEST(dns_cache_lookup_retains_multiple_answers_from_one_response) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        answer_add_a(&put_args, put_args.key, 0x7f01a8cc, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_TRUE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, SD_RESOLVED_CONFIDENTIAL);

        ASSERT_EQ(dns_answer_size(ret_answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f01a8cc);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);
}

TEST(dns_cache_lookup_nxdomain) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;
        dns_answer_add_soa(put_args.answer, "example.com", 3600, 0);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_TRUE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_NXDOMAIN);
        ASSERT_EQ(ret_query_flags, (SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL));

        ASSERT_EQ(dns_answer_size(ret_answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->soa.mname = strdup("example.com");
        rr->soa.rname = strdup("root.example.com");
        rr->soa.serial = 1;
        rr->soa.refresh = 1;
        rr->soa.retry = 1;
        rr->soa.expire = 1;
        rr->soa.minimum = 3600;
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
}

TEST(dns_cache_lookup_any_always_misses) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_FALSE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 0u);
        ASSERT_EQ(cache.n_miss, 1u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, 0u);

        ASSERT_EQ(dns_answer_size(ret_answer), 0u);
}

/* ================================================================
 * dns_cache_dump()
 * ================================================================ */

static int cmpstring(const void *a, const void *b) {
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        return strcmp(*(const char **)a, *(const char **)b);
}

static void check_dump_contents(FILE *f, const char **expected, size_t n) {
        char *actual[n];
        rewind(f);

        for (size_t i = 0; i < n; i++) {
                size_t length = read_line(f, 1024, &actual[i]);
                ASSERT_GT(length, 0u);
        }

        qsort(actual, n, sizeof(char *), cmpstring);

        for (size_t i = 0; i < n; i++)
                ASSERT_STREQ(actual[i], expected[i]);

        for (size_t i = 0; i < n; i++)
                free(actual[i]);
}

TEST(dns_cache_dump_single_a) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-cache-dump-single-a-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_cache_dump(&cache, f);

        const char *expected[] = {
                "\twww.example.com IN A 192.168.1.127"
        };
        check_dump_contents(f, expected, 1);
}

TEST(dns_cache_dump_a_with_cname) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_cname(&put_args, key, "example.com", 3600, DNS_ANSWER_CACHEABLE);

        dns_resource_key_unref(key);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 2u);

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-cache-dump-a-with-cname-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_cache_dump(&cache, f);

        const char *expected[] = {
                "\texample.com IN A 192.168.1.127",
                "\twww.example.com IN CNAME example.com"
        };
        check_dump_contents(f, expected, 2);
}

/* ================================================================
 * dns_cache_dump_to_json()
 * ================================================================ */

TEST(dns_cache_dump_json_basic) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL, *expected = NULL;
        sd_json_variant *item = NULL, *rr = NULL;
        _cleanup_free_ char *str = calloc(256, sizeof(char));

        ASSERT_NOT_NULL(str);

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        ASSERT_EQ(dns_cache_size(&cache), 1u);

        ASSERT_OK(dns_cache_dump_to_json(&cache, &json));
        ASSERT_NOT_NULL(json);

        ASSERT_TRUE(sd_json_variant_is_array(json));
        ASSERT_EQ(sd_json_variant_elements(json), 1u);

        item = BY_IDX(json, 0);
        ASSERT_NOT_NULL(item);

        sprintf(str, "{ \"class\": %d, \"type\": %d, \"name\": \"www.example.com\" }", DNS_CLASS_IN, DNS_TYPE_A);
        ASSERT_OK(sd_json_parse(str, 0, &expected, NULL, NULL));
        ASSERT_TRUE(sd_json_variant_equal(BY_KEY(item, "key"), expected));

        ASSERT_TRUE(sd_json_variant_is_array(BY_KEY(item, "rrs")));
        ASSERT_EQ(sd_json_variant_elements(BY_KEY(item, "rrs")), 1u);

        rr = BY_KEY(BY_IDX(BY_KEY(item, "rrs"), 0), "rr");
        ASSERT_NOT_NULL(rr);
        ASSERT_TRUE(sd_json_variant_equal(BY_KEY(rr, "key"), expected));

        sd_json_variant_unref(expected);

        sprintf(str, "[192, 168, 1, 127]");
        ASSERT_OK(sd_json_parse(str, 0, &expected, NULL, NULL));
        ASSERT_TRUE(sd_json_variant_equal(BY_KEY(rr, "address"), expected));

        ASSERT_TRUE(sd_json_variant_is_string(BY_KEY(BY_IDX(BY_KEY(item, "rrs"), 0), "raw")));
        ASSERT_TRUE(sd_json_variant_is_integer(BY_KEY(item, "until")));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
