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

static char* checked_strdup(const char *str) {
        char *copy = strdup(str);
        ASSERT_NOT_NULL(copy);
        return copy;
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
        rr->cname.name = checked_strdup(alias);
        rr->ttl = ttl;
        dns_answer_add(args->answer, rr, 1, flags, NULL);
}

static void answer_add_opt(PutArgs *args, DnsResourceKey *key, int ttl, DnsAnswerFlags flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new(key);
        ASSERT_NOT_NULL(rr);
        rr->opt.data_size = 0;
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

TEST(dns_a_success_mdns_no_key_is_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        put_args.protocol = DNS_PROTOCOL_MDNS;
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_FALSE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_mdns_update_existing) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        DnsResourceKey *key = NULL;

        args1.protocol = DNS_PROTOCOL_MDNS;
        args1.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        ASSERT_OK(cache_put(&cache, &args1));

        args2.protocol = DNS_PROTOCOL_MDNS;
        args2.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args2, key, 0xc0a8017f, 2400, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        ASSERT_OK(cache_put(&cache, &args2));

        ASSERT_EQ(dns_cache_size(&cache), 1u);
}

TEST(dns_a_success_mdns_zero_ttl_removes_existing) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        DnsResourceKey *key = NULL;

        args1.protocol = DNS_PROTOCOL_MDNS;
        args1.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        ASSERT_OK(cache_put(&cache, &args1));

        args2.protocol = DNS_PROTOCOL_MDNS;
        args2.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args2, key, 0xc0a8017f, 0, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        ASSERT_OK(cache_put(&cache, &args2));

        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_mdns_same_key_different_payloads) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        DnsResourceKey *key = NULL;

        put_args.protocol = DNS_PROTOCOL_MDNS;
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0x7f01a8cc, 2400, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(put_args.answer), 2u);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_EQ(dns_cache_size(&cache), 1u);
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

TEST(dns_a_success_any_class_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_any_type_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_opt(&put_args, put_args.key, 3600, DNS_ANSWER_CACHEABLE);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_success_opt_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_OPT, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_SUCCESS;
        answer_add_opt(&put_args, put_args.key, 3600, DNS_ANSWER_CACHEABLE);

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

TEST(dns_a_nxdomain_no_soa_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_nxdomain_any_class_is_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;
        dns_answer_add_soa(put_args.answer, "example.com", 3600, 0);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_nxdomain_any_type_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;
        dns_answer_add_soa(put_args.answer, "example.com", 3600, 0);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
}

TEST(dns_a_nxdomain_opt_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_OPT, "www.example.com");
        ASSERT_NOT_NULL(put_args.key);
        put_args.rcode = DNS_RCODE_NXDOMAIN;
        dns_answer_add_soa(put_args.answer, "example.com", 3600, 0);

        ASSERT_OK(cache_put(&cache, &put_args));
        ASSERT_TRUE(dns_cache_is_empty(&cache));
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
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

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

TEST(dns_cache_lookup_clamp_ttl) {
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
        query_flags = SD_RESOLVED_CLAMP_TTL;
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

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
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

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
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

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
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_NXDOMAIN);
        ASSERT_EQ(ret_query_flags, (SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL));

        ASSERT_EQ(dns_answer_size(ret_answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->soa.mname = checked_strdup("example.com");
        rr->soa.rname = checked_strdup("root.example.com");
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

TEST(dns_cache_lookup_mdns_multiple_shared_responses_are_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        args1.protocol = DNS_PROTOCOL_MDNS;
        args1.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        ASSERT_OK(cache_put(&cache, &args1));
        dns_resource_key_unref(key);

        args2.protocol = DNS_PROTOCOL_MDNS;
        args2.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args2, key, 0x7f01a8cc, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        ASSERT_OK(cache_put(&cache, &args2));
        dns_resource_key_unref(key);

        ASSERT_FALSE(dns_cache_is_empty(&cache));
        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, SD_RESOLVED_CONFIDENTIAL);

        ASSERT_EQ(dns_answer_size(ret_answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f01a8cc);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);
}

TEST(dns_cache_lookup_mdns_multiple_unshared_responses_are_not_cached) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        _cleanup_(dns_answer_unrefp) DnsAnswer *ret_answer = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *ret_full_packet = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        int query_flags, ret_rcode;
        uint64_t ret_query_flags;

        args1.protocol = DNS_PROTOCOL_MDNS;
        args1.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        ASSERT_OK(cache_put(&cache, &args1));
        dns_resource_key_unref(key);

        args2.protocol = DNS_PROTOCOL_MDNS;
        args2.rcode = DNS_RCODE_SUCCESS;
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args2, key, 0x7f01a8cc, 3600, DNS_ANSWER_CACHEABLE);
        ASSERT_OK(cache_put(&cache, &args2));
        dns_resource_key_unref(key);

        ASSERT_FALSE(dns_cache_is_empty(&cache));
        ASSERT_EQ(dns_cache_size(&cache), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        query_flags = 0;
        ASSERT_OK_POSITIVE(dns_cache_lookup(&cache, key, query_flags, &ret_rcode, &ret_answer, &ret_full_packet, &ret_query_flags, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(cache.n_hit, 1u);
        ASSERT_EQ(cache.n_miss, 0u);

        ASSERT_EQ(ret_rcode, DNS_RCODE_SUCCESS);
        ASSERT_EQ(ret_query_flags, SD_RESOLVED_CONFIDENTIAL);

        ASSERT_EQ(dns_answer_size(ret_answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_FALSE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f01a8cc);
        ASSERT_TRUE(dns_answer_contains(ret_answer, rr));
        dns_resource_record_unref(rr);
}

/* ================================================================
 * dns_cache_prune(), dns_cache_expiry_in_one_second()
 * ================================================================ */

TEST(dns_cache_prune) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 1, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns2.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0x7f01a8cc, 3, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        cache_put(&cache, &put_args);

        dns_cache_prune(&cache);
        ASSERT_EQ(dns_cache_size(&cache), 2u);
        ASSERT_TRUE(dns_cache_expiry_in_one_second(&cache, now(CLOCK_BOOTTIME)));

        sleep(2);

        dns_cache_prune(&cache);
        ASSERT_EQ(dns_cache_size(&cache), 1u);
        ASSERT_TRUE(dns_cache_expiry_in_one_second(&cache, now(CLOCK_BOOTTIME)));

        sleep(2);

        dns_cache_prune(&cache);
        ASSERT_TRUE(dns_cache_is_empty(&cache));
        ASSERT_FALSE(dns_cache_expiry_in_one_second(&cache, now(CLOCK_BOOTTIME)));
}

/* ================================================================
 * dns_cache_check_conflicts()
 * ================================================================ */

TEST(dns_cache_check_conflicts_same_key_and_owner) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(put_args.key);
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        union in_addr_union owner_addr = { .in.s_addr = htobe32(0x01020304) };

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(rr);
        ASSERT_FALSE(dns_cache_check_conflicts(&cache, rr, AF_INET, &owner_addr));
}

TEST(dns_cache_check_conflicts_same_key_different_owner) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(put_args.key);
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        union in_addr_union owner_addr = { .in.s_addr = htobe32(0x01020305) };

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(rr);
        ASSERT_TRUE(dns_cache_check_conflicts(&cache, rr, AF_INET, &owner_addr));
}

TEST(dns_cache_check_conflicts_different_key) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        put_args.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns2.example.com");
        ASSERT_NOT_NULL(put_args.key);
        answer_add_a(&put_args, put_args.key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &put_args);

        union in_addr_union owner_addr = { .in.s_addr = htobe32(0x01020305) };

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(rr);
        ASSERT_FALSE(dns_cache_check_conflicts(&cache, rr, AF_INET, &owner_addr));
}

/* ================================================================
 * dns_cache_export_shared_to_packet()
 * ================================================================ */

TEST(dns_cache_export_shared_to_packet) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs args1 = mk_put_args(), args2 = mk_put_args();
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        args1.protocol = DNS_PROTOCOL_MDNS;
        args1.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "shared.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "unshared.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&args1, key, 0xa87f01c0, 2400, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        cache_put(&cache, &args1);

        args2.protocol = DNS_PROTOCOL_DNS;
        args2.key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "dns.example.com");
        ASSERT_NOT_NULL(args2.key);
        args2.rcode = DNS_RCODE_SUCCESS;
        answer_add_a(&args2, args2.key, 0xa9fe0100, 2400, DNS_ANSWER_CACHEABLE);
        cache_put(&cache, &args2);

        dns_packet_new(&packet, DNS_PROTOCOL_MDNS, 0, DNS_PACKET_SIZE_MAX);
        ASSERT_NOT_NULL(packet);
        ASSERT_OK(dns_cache_export_shared_to_packet(&cache, packet, 0, 50));

        const uint8_t data[] = {
                        0x00, 0x00,     0x00, 0x00,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x06, 's', 'h', 'a', 'r', 'e', 'd',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_EQ(packet->size, sizeof(data));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet), data, sizeof(data)), 0);
}

TEST(dns_cache_export_shared_to_packet_multi) {
        _cleanup_(dns_cache_unrefp) DnsCache cache = new_cache();
        _cleanup_(put_args_unrefp) PutArgs put_args = mk_put_args();
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        put_args.protocol = DNS_PROTOCOL_MDNS;
        put_args.rcode = DNS_RCODE_SUCCESS;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "shared1.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xc0a8017f, 3600, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "unshared.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0xa87f01c0, 2400, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "shared2.example.com");
        ASSERT_NOT_NULL(key);
        answer_add_a(&put_args, key, 0x7f01a8cc, 1800, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SHARED_OWNER);
        dns_resource_key_unref(key);

        cache_put(&cache, &put_args);

        dns_packet_new(&packet, DNS_PROTOCOL_MDNS, 0, DNS_PACKET_SIZE_MAX);
        ASSERT_NOT_NULL(packet);
        ASSERT_OK(dns_cache_export_shared_to_packet(&cache, packet, 0, 1));

        const uint8_t data1[] = {
                        0x00, 0x00,     0x00, 0x00,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 's', 'h', 'a', 'r', 'e', 'd', '1',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        const uint8_t data2[] = {
                        0x00, 0x00,     0x00, 0x00,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 's', 'h', 'a', 'r', 'e', 'd', '2',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x07, 0x08,
        /* rdata */     0x00, 0x04,
        /* ip */        0x7f, 0x01, 0xa8, 0xcc
        };

        size_t size1 = sizeof(data1), size2 = sizeof(data2);

        /* cache key order is not deterministic; the packets could come out in either order */

        if (memcmp(DNS_PACKET_DATA(packet), data1, size1) == 0) {
                ASSERT_EQ(packet->size, size1);
                ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet), data1, size1), 0);

                ASSERT_EQ(packet->more->size, size2);
                ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet->more), data2, size2), 0);
        } else {
                ASSERT_EQ(packet->size, size2);
                ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet), data2, size2), 0);

                ASSERT_EQ(packet->more->size, size1);
                ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet->more), data1, size1), 0);
        }

        ASSERT_NULL(packet->more->more);
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
