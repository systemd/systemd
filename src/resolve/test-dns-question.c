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

/* ================================================================
 * dns_question_new_reverse()
 * ================================================================ */

TEST(dns_question_new_reverse_ipv4) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        union in_addr_union addr = { .in.s_addr = htobe32(0xc0a8017f) };

        ASSERT_OK(dns_question_new_reverse(&question, AF_INET, &addr));
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "127.1.168.192.in-addr.arpa");

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

/* ================================================================
 * dns_question_new_service()
 * ================================================================ */

TEST(dns_question_new_service_no_domain) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_ERROR(dns_question_new_service(&question, NULL, "_xmpp._tcp", NULL, 0, 0), EINVAL);
        ASSERT_NULL(question);
}

TEST(dns_question_new_service_domain_only) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, NULL, NULL, "www.example.com", 0, 0));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_service_domain_ignores_idna) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, NULL, NULL, "\xF0\x9F\x98\xB1.com", 0, 1));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "\xF0\x9F\x98\xB1.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_service_with_type) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, NULL, "_xmpp._tcp", "example.com", 0, 0));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.example.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_service_with_type_applies_idna) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, NULL, "_xmpp._tcp", "\xF0\x9F\x98\xB1.com", 0, 1));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.xn--s38h.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_service_with_type_with_txt) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, NULL, "_xmpp._tcp", "\xF0\x9F\x98\xB1.com", 1, 1));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.xn--s38h.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, "_xmpp._tcp.xn--s38h.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
        dns_resource_key_unref(key);
}

TEST(dns_question_new_service_with_invalid_type) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_ERROR(dns_question_new_service(&question, NULL, "_xmpp.tcp", "example.com", 0, 0), EINVAL);
        ASSERT_NULL(question);
}

TEST(dns_question_new_service_with_type_too_short) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_ERROR(dns_question_new_service(&question, NULL, "_xmpp", "example.com", 0, 0), EINVAL);
        ASSERT_NULL(question);
}

TEST(dns_question_new_service_with_type_too_long) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_ERROR(dns_question_new_service(&question, NULL, "_xmpp._tcp._extra", "example.com", 0, 0), EINVAL);
        ASSERT_NULL(question);
}

TEST(dns_question_new_service_with_service_and_type) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_service(&question, "service", "_xmpp._tcp", "example.com", 0, 0));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "service._xmpp._tcp.example.com");
        ASSERT_TRUE(dns_question_contains_key(question, key));
}

TEST(dns_question_new_service_with_service_no_type) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_ERROR(dns_question_new_service(&question, "service", NULL, "example.com", 0, 0), EINVAL);
        ASSERT_NULL(question);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
