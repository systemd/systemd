/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * dns_answer_add()
 * ================================================================ */

TEST(dns_answer_add_a) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        answer = dns_answer_new(0);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

/* ================================================================
 * dns_answer_match_key()
 * ================================================================ */

TEST(dns_answer_match_key_single) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags = 0;

        answer = dns_answer_new(0);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        ASSERT_EQ(dns_answer_size(answer), 1u);

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, &flags));
        ASSERT_EQ((int)flags, DNS_ANSWER_CACHEABLE);

        /* ANY class matches */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* ANY type matches */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* name is case-insensitive */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "WWW.EXAMPLE.COM");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* name containing an error */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL) == -EINVAL);
        dns_resource_key_unref(key);
}

TEST(dns_answer_match_key_multiple) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        DnsAnswerFlags shared_flags = DNS_ANSWER_SECTION_ANSWER, ret_flags = 0;

        answer = dns_answer_new(0);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        dns_answer_add(answer, rr, 1, shared_flags | DNS_ANSWER_AUTHENTICATED, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, shared_flags | DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_answer_size(answer), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, &ret_flags));
        ASSERT_EQ(ret_flags, shared_flags | DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, &ret_flags));
        ASSERT_EQ(ret_flags, shared_flags);
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_find_soa()
 * ================================================================ */

TEST(dns_answer_find_soa) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags = 0;

        answer = dns_answer_new(0);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        dns_answer_add_soa(answer, "example.com", 3600, 1);

        /* does not find SOA keys */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* finds matching A key */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        ASSERT_EQ((int)flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        /* finds matching A key suddomain */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "foo.www.example.com");
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        ASSERT_EQ((int)flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        /* does not match simple prefix */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "fooexample.com");
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* does not match parent domain */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "com");
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* returns an error for bad escapes */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        ASSERT_ERROR(dns_answer_find_soa(answer, key, &rr, &flags), EINVAL);
        dns_resource_key_unref(key);
}

TEST(dns_answer_find_soa_multi) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags = 0;

        answer = dns_answer_new(0);

        dns_answer_add_soa(answer, "example.com", 3600, 1);
        dns_answer_add_soa(answer, "example.org", 3600, 1);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.org");
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_merge()
 * ================================================================ */

TEST(dns_answer_merge_same_object) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *ret = NULL;

        a = dns_answer_new(0);

        ASSERT_OK(dns_answer_merge(a, a, &ret));
        ASSERT_TRUE(ret == a);
}

TEST(dns_answer_merge_a_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;

        a = dns_answer_new(0);
        b = dns_answer_new(0);

        dns_answer_add_soa(b, "example.com", 3600, 1);

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret != a);
        ASSERT_TRUE(ret == b);
}

TEST(dns_answer_merge_b_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;

        a = dns_answer_new(0);
        b = dns_answer_new(0);

        dns_answer_add_soa(a, "example.com", 3600, 1);

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret == a);
        ASSERT_TRUE(ret != b);
}

TEST(dns_answer_merge_non_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        a = dns_answer_new(0);
        b = dns_answer_new(0);

        rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, NULL);

        rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr_b->a.in_addr.s_addr = htobe32(0xc0a80180);
        dns_answer_add(b, rr_b, 1, DNS_ANSWER_CACHEABLE, NULL);

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret != a);
        ASSERT_TRUE(ret != b);

        ASSERT_TRUE(dns_answer_match_key(a, rr_a->key, NULL));
        ASSERT_FALSE(dns_answer_match_key(a, rr_b->key, NULL));

        ASSERT_TRUE(dns_answer_match_key(b, rr_b->key, NULL));
        ASSERT_FALSE(dns_answer_match_key(b, rr_a->key, NULL));

        ASSERT_TRUE(dns_answer_match_key(ret, rr_a->key, NULL));
        ASSERT_TRUE(dns_answer_match_key(ret, rr_b->key, NULL));
}

/* ================================================================
 * dns_answer_extend()
 * ================================================================ */

TEST(dns_answer_replace_non_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        a = dns_answer_new(0);
        b = dns_answer_new(0);

        rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, NULL);

        rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr_b->a.in_addr.s_addr = htobe32(0xc0a80180);
        dns_answer_add(b, rr_b, 1, DNS_ANSWER_CACHEABLE, NULL);

        ASSERT_OK(dns_answer_extend(&a, b));
        ASSERT_TRUE(a != b);

        ASSERT_TRUE(dns_answer_match_key(a, rr_a->key, NULL));
        ASSERT_TRUE(dns_answer_match_key(a, rr_b->key, NULL));

        ASSERT_TRUE(dns_answer_match_key(b, rr_b->key, NULL));
        ASSERT_FALSE(dns_answer_match_key(b, rr_a->key, NULL));
}

/* ================================================================
 * dns_answer_remove_by_*()
 * ================================================================ */

static DnsAnswer* prepare_answer(void) {
        DnsAnswer *answer = dns_answer_new(0);
        DnsResourceRecord *rr = NULL;
        int i;

        const char *hosts[] = {
                "a.example.com",
                "b.example.com",
                "c.example.com"
        };

        for (i = 0; i < 3; i++) {
                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, hosts[i]);
                rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
                dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
                dns_resource_record_unref(rr);
        }

        return answer;
}

TEST(dns_answer_remove_by_key_single) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key = NULL;

        /* ignore non-matching class */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "b.example.com");
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "b.example.com");
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "z.example.com");
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* remove matching key */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_TRUE(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 2u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_remove_by_key_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        ASSERT_NULL(answer);
}

TEST(dns_answer_remove_by_rr_single) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* remove nothing if the payload does not match */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0x01020304);
        ASSERT_FALSE(dns_answer_remove_by_rr(&answer, rr));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_record_unref(rr);

        /* remove matching payload */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_TRUE(dns_answer_remove_by_rr(&answer, rr));
        ASSERT_EQ(dns_answer_size(answer), 2u);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_remove_by_rr_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_remove_by_rr(&answer, rr);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_remove_by_rr(&answer, rr);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_remove_by_rr(&answer, rr);
        dns_resource_record_unref(rr);

        ASSERT_NULL(answer);
}

TEST(dns_answer_remove_by_answer_keys_partial) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = prepare_answer();
        _cleanup_(dns_answer_unrefp) DnsAnswer *b = prepare_answer();

        dns_answer_remove_by_answer_keys(&a, b);

        ASSERT_NULL(a);
}

TEST(dns_answer_remove_by_answer_keys_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = prepare_answer();
        _cleanup_(dns_answer_unrefp) DnsAnswer *b = prepare_answer();
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        dns_answer_remove_by_key(&b, key);
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(a), 3u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        dns_answer_remove_by_answer_keys(&a, b);

        ASSERT_EQ(dns_answer_size(a), 1u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_FALSE(dns_answer_match_key(a, key, NULL));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_TRUE(dns_answer_match_key(a, key, NULL));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_FALSE(dns_answer_match_key(a, key, NULL));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_copy_by_key()
 * ================================================================ */

TEST(dns_answer_copy_by_key_no_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        /* non-matching class */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_single_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 1u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_multi_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 2u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_flags) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        DnsAnswerFlags ret_flags = 0;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 1u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, &ret_flags));
        ASSERT_EQ((int)ret_flags, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, DNS_ANSWER_SECTION_ANSWER, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 2u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, &ret_flags));
        ASSERT_EQ((int)ret_flags, (DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_move_by_key()
 * ================================================================ */

TEST(dns_answer_move_by_key_no_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        /* non-matching class */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com");
        ASSERT_FALSE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com");
        ASSERT_FALSE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_FALSE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);
}

TEST(dns_answer_move_by_key_single_destroy_source) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_NULL(source);
        ASSERT_EQ(dns_answer_size(target), 1u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_move_by_key_single_leave_source) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 1u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_move_by_key_multi_leave_source) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        rr->a.in_addr.s_addr = htobe32(0xc0a80180);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 2u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
