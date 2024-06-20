/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "resolved-dns-query.h"
#include "resolved-dns-rr.h"
#include "resolved-manager.h"
#include "tests.h"

/* ================================================================
 * dns_query_new()
 * ================================================================ */

TEST(dns_query_new_single_question) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_multi_question_same_domain) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceKey *key = NULL;

        question = dns_question_new(2);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, 0));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, 0));
        dns_resource_key_unref(key);

        ASSERT_OK(dns_query_new(&manager, &query, question, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_multi_question_different_domain) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceKey *key = NULL;

        question = dns_question_new(2);
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "ns1.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, 0));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "ns2.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, 0));
        dns_resource_key_unref(key);

        ASSERT_ERROR(dns_query_new(&manager, &query, question, NULL, NULL, 1, 0), EINVAL);
        ASSERT_NULL(query);
}

#if HAVE_LIBIDN || HAVE_LIBIDN2
TEST(dns_query_new_same_utf8_and_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x98\xB1.com", true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, NULL, 1, 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_different_utf8_and_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, NULL, 1, 0));
        ASSERT_NOT_NULL(query);
}
#endif

TEST(dns_query_new_bypass_ok) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_packet_append_question(packet, question));

        ASSERT_OK(dns_query_new(&manager, &query, NULL, NULL, packet, 1, 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_bypass_conflict) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL, *extra_q = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_packet_append_question(packet, question));

        ASSERT_OK(dns_question_new_address(&extra_q, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(extra_q);

        ASSERT_ERROR(dns_query_new(&manager, &query, extra_q, NULL, packet, 1, 0), EINVAL);
        ASSERT_NULL(query);
}

#define MAX_QUERIES 2048

TEST(dns_query_new_too_many_questions) {
        Manager manager = {};
        DnsQuestion *question = NULL;
        DnsQuery *queries[MAX_QUERIES + 1];

        for (size_t i = 0; i < MAX_QUERIES; i++) {
                ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
                ASSERT_NOT_NULL(question);

                ASSERT_OK(dns_query_new(&manager, &queries[i], question, NULL, NULL, 1, 0));
                ASSERT_NOT_NULL(queries[i]);

                dns_question_unref(question);
        }

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_ERROR(dns_query_new(&manager, &queries[MAX_QUERIES], question, NULL, NULL, 1, 0), EBUSY);
        dns_question_unref(question);

        for (size_t i = 0; i < MAX_QUERIES; i++)
                dns_query_free(queries[i]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
