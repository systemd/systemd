/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * dns_question_add()
 * ================================================================ */

TEST(dns_question_add_full) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        question = dns_question_new(0);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_ERROR(dns_question_add(question, key, 0), ENOSPC);

        ASSERT_FALSE(dns_question_contains_key(question, key));

        assert(dns_question_size(question) == 0);
        assert(dns_question_isempty(question) == 1);
}

TEST(dns_question_add_with_space) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        assert(dns_question_size(question) == 0);
        assert(dns_question_isempty(question) == 1);

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_question_contains_key(question, key));

        assert(dns_question_size(question) == 1);
        assert(dns_question_isempty(question) == 0);
}

/* ================================================================
 * dns_question_new_address()
 * ================================================================ */

TEST(dns_question_new_address_ipv4) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", 0));
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_address_ipv6) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET6, "www.example.com", 0));
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_address_convert_idna) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.\xF0\x9F\x98\xB1.com", 1));
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.xn--s38h.com");

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
