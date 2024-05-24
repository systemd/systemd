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
        DnsResourceRecord *rr = NULL;
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

DEFINE_TEST_MAIN(LOG_DEBUG);
