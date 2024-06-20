/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "resolved-dns-query.h"
#include "resolved-dns-rr.h"
#include "resolved-manager.h"
#include "tests.h"

static char* checked_strdup(const char *str) {
        char *copy = strdup(str);
        ASSERT_NOT_NULL(copy);
        return copy;
}

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

/* ================================================================
 * dns_query_make_auxiliary()
 * ================================================================ */

TEST(dns_query_make_auxiliary) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *qn1 = NULL, *qn2 = NULL, *qn3 = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q1 = NULL, *q2 = NULL, *q3 = NULL;

        ASSERT_OK(dns_question_new_address(&qn1, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(qn1);
        ASSERT_OK(dns_query_new(&manager, &q1, qn1, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(q1);

        ASSERT_OK(dns_question_new_address(&qn2, AF_INET, "www.example.net", false));
        ASSERT_NOT_NULL(qn2);
        ASSERT_OK(dns_query_new(&manager, &q2, qn2, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(q2);

        ASSERT_OK(dns_question_new_address(&qn3, AF_INET, "www.example.org", false));
        ASSERT_NOT_NULL(qn3);
        ASSERT_OK(dns_query_new(&manager, &q3, qn3, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(q3);

        ASSERT_OK(dns_query_make_auxiliary(q2, q1));
        ASSERT_OK(dns_query_make_auxiliary(q3, q1));

        ASSERT_EQ(q1->n_auxiliary_queries, 2u);
        ASSERT_TRUE(q1->auxiliary_queries == q3);
        ASSERT_TRUE(q1->auxiliary_queries->auxiliary_queries_next == q2);

        ASSERT_TRUE(q2->auxiliary_for == q1);
        ASSERT_TRUE(q3->auxiliary_for == q1);
}

/* ================================================================
 * dns_query_process_cname_one()
 * ================================================================ */

TEST(dns_query_process_cname_one_null) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_MATCH);
}

TEST(dns_query_process_cname_one_success_exact_match) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_MATCH);

        ASSERT_EQ(query->n_cname_redirects, 0u);
}

TEST(dns_query_process_cname_one_success_match_cname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer_query_flags = SD_RESOLVED_FROM_NETWORK;
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_FALSE(dns_query_fully_authenticated(query));
        ASSERT_FALSE(dns_query_fully_confidential(query));
        ASSERT_FALSE(dns_query_fully_authoritative(query));

        ASSERT_GT(query->flags & SD_RESOLVED_NO_SEARCH, 0u);

        ASSERT_EQ(query->n_cname_redirects, 1u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 1u);
        ASSERT_NULL(query->question_utf8);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_idna, key));
        dns_resource_key_unref(key);
}

TEST(dns_query_process_cname_one_success_flags) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        query->answer_query_flags = SD_RESOLVED_FROM_NETWORK |
                                SD_RESOLVED_AUTHENTICATED |
                                SD_RESOLVED_CONFIDENTIAL |
                                SD_RESOLVED_SYNTHETIC;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_TRUE(dns_query_fully_authenticated(query));
        ASSERT_TRUE(dns_query_fully_confidential(query));
        ASSERT_TRUE(dns_query_fully_authoritative(query));
}

/* ================================================================
 * dns_query_process_cname_many()
 * ================================================================ */

TEST(dns_query_process_cname_many_success_match_multiple_cname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer_query_flags = SD_RESOLVED_FROM_NETWORK;
        query->answer = dns_answer_new(4);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("tmp1.example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp2.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp1.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("tmp2.example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_many(query), DNS_QUERY_MATCH);

        ASSERT_FALSE(dns_query_fully_authenticated(query));
        ASSERT_FALSE(dns_query_fully_confidential(query));
        ASSERT_FALSE(dns_query_fully_authoritative(query));

        ASSERT_GT(query->flags & SD_RESOLVED_NO_SEARCH, 0u);

        ASSERT_EQ(query->n_cname_redirects, 3u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 3u);
        ASSERT_NULL(query->question_utf8);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "tmp1.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "tmp2.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_idna, key));
        dns_resource_key_unref(key);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
