/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "tmpfile-util.h"

/* ================================================================
 * dns_answer_add()
 * ================================================================ */

TEST(dns_answer_add_a) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
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
        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        ASSERT_EQ(dns_answer_size(answer), 1u);

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));

        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, &flags));
        ASSERT_EQ((int)flags, DNS_ANSWER_CACHEABLE);

        /* ANY class matches */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* ANY type matches */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* name is case-insensitive */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "WWW.EXAMPLE.COM");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* name containing an error */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL) == -EINVAL);
        dns_resource_key_unref(key);
}

TEST(dns_answer_match_key_multiple) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        DnsAnswerFlags shared_flags = DNS_ANSWER_SECTION_ANSWER, ret_flags = 0;

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        ASSERT_NOT_NULL(rr);
        dns_answer_add(answer, rr, 1, shared_flags | DNS_ANSWER_AUTHENTICATED, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, shared_flags | DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_answer_size(answer), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, &ret_flags));
        ASSERT_EQ(ret_flags, shared_flags | DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        ASSERT_NOT_NULL(key);
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
        ASSERT_NOT_NULL(answer);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        dns_answer_add_soa(answer, "example.com", 3600, 1);

        /* does not find SOA keys */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* finds matching A key */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        ASSERT_EQ((int)flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        /* finds matching A key suddomain */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "foo.www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        ASSERT_EQ((int)flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        /* does not match simple prefix */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "fooexample.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* does not match parent domain */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        /* returns an error for bad escapes */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_ERROR(dns_answer_find_soa(answer, key, &rr, &flags), EINVAL);
        dns_resource_key_unref(key);
}

TEST(dns_answer_find_soa_multi) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        DnsAnswerFlags flags = 0;

        answer = dns_answer_new(0);
        ASSERT_NOT_NULL(answer);

        dns_answer_add_soa(answer, "example.com", 3600, 1);
        dns_answer_add_soa(answer, "example.org", 3600, 1);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.org");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_merge()
 * ================================================================ */

TEST(dns_answer_merge_same_object) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *ret = NULL;

        a = dns_answer_new(0);
        ASSERT_NOT_NULL(a);

        ASSERT_OK(dns_answer_merge(a, a, &ret));
        ASSERT_TRUE(ret == a);
}

TEST(dns_answer_merge_a_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;

        a = dns_answer_new(0);
        ASSERT_NOT_NULL(a);

        b = dns_answer_new(0);
        ASSERT_NOT_NULL(b);

        dns_answer_add_soa(b, "example.com", 3600, 1);

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret != a);
        ASSERT_TRUE(ret == b);
}

TEST(dns_answer_merge_b_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;

        a = dns_answer_new(0);
        ASSERT_NOT_NULL(a);

        b = dns_answer_new(0);
        ASSERT_NOT_NULL(b);

        dns_answer_add_soa(a, "example.com", 3600, 1);

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret == a);
        ASSERT_TRUE(ret != b);
}

TEST(dns_answer_merge_non_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        a = dns_answer_new(0);
        ASSERT_NOT_NULL(a);

        b = dns_answer_new(0);
        ASSERT_NOT_NULL(b);

        rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr_a);
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, NULL);

        rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr_b);
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
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        a = dns_answer_new(0);
        ASSERT_NOT_NULL(a);

        b = dns_answer_new(0);
        ASSERT_NOT_NULL(b);

        rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr_a);
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, NULL);

        rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr_b);
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

        ASSERT_NOT_NULL(answer);

        const char *hosts[] = {
                "a.example.com",
                "b.example.com",
                "c.example.com"
        };

        for (i = 0; i < 3; i++) {
                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, hosts[i]);
                ASSERT_NOT_NULL(rr);
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
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "z.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* remove matching key */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 2u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_remove_by_key_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_NOT_NULL(key);
        dns_answer_remove_by_key(&answer, key);
        dns_resource_key_unref(key);

        ASSERT_NULL(answer);
}

TEST(dns_answer_remove_by_rr_single) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);

        /* remove nothing if the payload does not match */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x01020304);
        ASSERT_FALSE(dns_answer_remove_by_rr(&answer, rr));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_record_unref(rr);

        /* remove matching payload */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_TRUE(dns_answer_remove_by_rr(&answer, rr));
        ASSERT_EQ(dns_answer_size(answer), 2u);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_match_key(answer, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_remove_by_rr_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_remove_by_rr(&answer, rr);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_remove_by_rr(&answer, rr);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_NOT_NULL(rr);
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
        ASSERT_NOT_NULL(key);
        dns_answer_remove_by_key(&b, key);
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(a), 3u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        dns_answer_remove_by_answer_keys(&a, b);

        ASSERT_EQ(dns_answer_size(a), 1u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_match_key(a, key, NULL));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(a, key, NULL));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_NOT_NULL(key);
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

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        /* non-matching class */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        ASSERT_TRUE(dns_answer_isempty(target));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_single_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 1u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_multi_match) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 2u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_copy_by_key_flags) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;
        DnsAnswerFlags ret_flags = 0;

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, 0, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 1u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(target, key, &ret_flags));
        ASSERT_EQ((int)ret_flags, DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, DNS_ANSWER_SECTION_ANSWER, NULL));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(target), 2u);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
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

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        /* non-matching class */
        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
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

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_NULL(source);
        ASSERT_EQ(dns_answer_size(target), 1u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_move_by_key_single_leave_source) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 1u);
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_match_key(target, key, NULL));
        dns_resource_key_unref(key);
}

TEST(dns_answer_move_by_key_multi_leave_source) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = dns_answer_new(0);
        _cleanup_(dns_answer_unrefp) DnsAnswer *target = dns_answer_new(0);
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(source);
        ASSERT_NOT_NULL(target);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0xc0a80180);
        dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_answer_move_by_key(&target, &source, key, 0, NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 2u);
}

/* ================================================================
 * dns_answer_has_dname_for_cname()
 * ================================================================ */

TEST(dns_answer_has_dname_for_cname_pass) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL;

        ASSERT_NOT_NULL(answer);

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.example.com");
        dns_answer_add(answer, dname, 1, DNS_ANSWER_CACHEABLE, NULL);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("www.v2.example.com");
        ASSERT_TRUE(dns_answer_has_dname_for_cname(answer, cname));
}

TEST(dns_answer_has_dname_for_cname_no_dname) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;

        ASSERT_NOT_NULL(answer);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("www.v2.example.com");
        ASSERT_FALSE(dns_answer_has_dname_for_cname(answer, cname));
}

TEST(dns_answer_has_dname_for_cname_no_match_old_suffix) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL;

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.examples.com");
        dns_answer_add(answer, dname, 1, DNS_ANSWER_CACHEABLE, NULL);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("www.v2.example.com");
        ASSERT_FALSE(dns_answer_has_dname_for_cname(answer, cname));
}

TEST(dns_answer_has_dname_for_cname_no_match_new_suffix) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL;

        ASSERT_NOT_NULL(answer);

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.example.com");
        dns_answer_add(answer, dname, 1, DNS_ANSWER_CACHEABLE, NULL);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("www.v3.example.com");
        ASSERT_FALSE(dns_answer_has_dname_for_cname(answer, cname));
}

TEST(dns_answer_has_dname_for_cname_not_cname) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL;

        ASSERT_NOT_NULL(answer);

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.example.com");
        dns_answer_add(answer, dname, 1, DNS_ANSWER_CACHEABLE, NULL);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_FALSE(dns_answer_has_dname_for_cname(answer, cname));
}

/* ================================================================
 * dns_answer_dump()
 * ================================================================ */

static void check_dump_contents(FILE *f, const char **expected, size_t n) {
        char *actual[n];
        size_t i, r;
        rewind(f);

        for (i = 0; i < n; i++) {
                r = read_line(f, 1024, &actual[i]);
                ASSERT_GT(r, 0u);
        }

        for (i = 0; i < n; i++)
                ASSERT_STREQ(actual[i], expected[i]);

        for (i = 0 ; i < n; i++)
                free(actual[i]);
}

TEST(dns_answer_dump) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_new(0);
        DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 1200;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ADDITIONAL, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 2400;
        rr->a.in_addr.s_addr = htobe32(0xc0a80180);
        dns_answer_add(answer, rr, 2, 0, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a80181);
        dns_answer_add(answer, rr, 3, DNS_ANSWER_AUTHENTICATED | DNS_ANSWER_SHARED_OWNER | DNS_ANSWER_SECTION_AUTHORITY | DNS_ANSWER_CACHE_FLUSH, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "d.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 4800;
        rr->cname.name = strdup("www.example.com");
        dns_answer_add(answer, rr, 4, DNS_ANSWER_GOODBYE | DNS_ANSWER_SECTION_ANSWER, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_answer_size(answer), 4u);

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-answer-dump-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_answer_dump(answer, f);

        const char *expected[] = {
                "\ta.example.com IN A 192.168.1.127\t; ttl=1200 ifindex=1 cacheable section-additional",
                "\tb.example.com IN A 192.168.1.128\t; ttl=2400 ifindex=2",
                "\tc.example.com IN A 192.168.1.129\t; ttl=3600 ifindex=3 authenticated shared-owner cache-flush section-authority",
                "\td.example.com IN CNAME www.example.com\t; ttl=4800 ifindex=4 goodbye section-answer"
        };
        check_dump_contents(f, expected, 4);
}

/* ================================================================
 * dns_answer_order_by_scope()
 * ================================================================ */

/* link-local addresses are a9fe0100 (169.254.1.0) to a9fefeff (169.254.254.255) */

static DnsAnswer* prepare_link_local_answer(void) {
        DnsAnswer *answer = dns_answer_new(0);
        DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fe0100);
        dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a80404);
        dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fefeff);
        dns_answer_add(answer, rr, 3, DNS_ANSWER_CACHEABLE, NULL);
        dns_resource_record_unref(rr);

        return answer;
}

TEST(dns_answer_order_by_scope_prefer_link_local) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_link_local_answer();
        dns_answer_order_by_scope(answer, 1);

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-answer-order-by-scope-1-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_answer_dump(answer, f);

        const char *expected[] = {
                "\ta.example.com IN A 169.254.1.0\t; ttl=3600 ifindex=1 cacheable",
                "\tc.example.com IN A 169.254.254.255\t; ttl=3600 ifindex=3 cacheable",
                "\tb.example.com IN A 192.168.4.4\t; ttl=3600 ifindex=2 cacheable"
        };
        check_dump_contents(f, expected, 3);
}

TEST(dns_answer_order_by_scope_prefer_other) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_link_local_answer();
        dns_answer_order_by_scope(answer, 0);

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-answer-order-by-scope-2-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_answer_dump(answer, f);

        const char *expected[] = {
                "\tb.example.com IN A 192.168.4.4\t; ttl=3600 ifindex=2 cacheable",
                "\ta.example.com IN A 169.254.1.0\t; ttl=3600 ifindex=1 cacheable",
                "\tc.example.com IN A 169.254.254.255\t; ttl=3600 ifindex=3 cacheable"
        };
        check_dump_contents(f, expected, 3);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
