/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "resolved-dns-query.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-server.h"
#include "resolved-link.h"
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

TEST(dns_query_process_cname_one_success_no_match) {
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

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "tmp.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_NOMATCH);

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

TEST(dns_query_process_cname_one_success_match_dname) {
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
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->dname.name = checked_strdup("v2.example.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_EQ(query->n_cname_redirects, 1u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 1u);
        ASSERT_NULL(query->question_utf8);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.v2.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_idna, key));
        dns_resource_key_unref(key);
}

#if HAVE_LIBIDN || HAVE_LIBIDN2
TEST(dns_query_process_cname_one_success_match_dname_utf8_same) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.xn--tl8h.com", false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "xn--tl8h.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->dname.name = checked_strdup("v2.xn--tl8h.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_EQ(query->n_cname_redirects, 1u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 1u);
        ASSERT_EQ(dns_question_size(query->question_utf8), 1u);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.v2.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_utf8, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.v2.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_idna, key));
        dns_resource_key_unref(key);
}

TEST(dns_query_process_cname_one_success_match_dname_utf8_different) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->state = DNS_TRANSACTION_SUCCESS;
        query->answer_protocol = DNS_PROTOCOL_DNS;
        query->answer_family = AF_INET;
        query->answer = dns_answer_new(1);
        ASSERT_NOT_NULL(query->answer);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "xn--tl8h.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->dname.name = checked_strdup("v2.xn--tl8h.com");
        dns_answer_add(query->answer, rr, 1, 0, NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_EQ(query->n_cname_redirects, 1u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 2u);
        ASSERT_NULL(query->question_utf8);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\xF0\x9F\x98\xB1.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.v2.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_idna, key));
        dns_resource_key_unref(key);
}
#endif

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

/* ================================================================
 * dns_query_string()
 * ================================================================ */

TEST(dns_query_string_question_utf8) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "utf8.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "utf8.example.com");
}

TEST(dns_query_string_question_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "idna.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, question, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "idna.example.com");
}

TEST(dns_query_string_question_bypass) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket * packet = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&packet->question, AF_INET, "bypass.example.com", false));
        ASSERT_NOT_NULL(packet->question);

        ASSERT_OK(dns_query_new(&manager, &query, NULL, NULL, packet, 1, 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "bypass.example.com");
}

TEST(dns_query_string_request_address) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, NULL, NULL, 1, 0));
        ASSERT_NOT_NULL(query);

        query->request_family = AF_INET;
        query->request_address.in.s_addr = htobe32(0x7f000001);
        query->request_address_valid = true;

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "127.0.0.1");
}

/* ================================================================
 * dns_query_go()
 * ================================================================ */

/* Testing this function is somewhat problematic since, in addition to setting up the state for query
 * candidates, their scopes and transactions, it also directly initiates I/O to files and the network. In
 * particular:
 *
 * - The very first thing it does is try to respond to the query by reading the system /etc/hosts file, which
 *   may be symlinked to a SystemD resource. Ideally we could test this without accessing global files.
 *
 * - dns_scope_get_dns_server() calls manager_get_dns_server(), which tries to read /etc/resolv.conf.
 *
 * - A potential solution to these issues would be to let these file paths be configured instead of
 *   hard-coded into the source.
 *
 * - dns_scope_good_domain(), by checking dns_scope_get_dns_server(), will not match with a scope that does
 *   not have a server configured, either on the scope's link (if it has one) or the manager's main/fallback
 *   server. Configuring a server means that dns_query_candidate_go() and then dns_transaction_go() will send
 *   UDP/TCP traffic to that server. Ideally we'd like to test that we can set up all the candidate and
 *   transaction state without actually causing any requests to be sent.
 */

typedef struct GoConfig {
        bool has_scope;
        bool use_link;
        bool use_bypass;
        size_t n_search_domains;
} GoConfig;

static GoConfig mk_go_config(void) {
        return (GoConfig) {
                .has_scope = true,
                .use_link = false,
                .use_bypass = false,
                .n_search_domains = 0
        };
}

typedef struct GoEnvironment {
        Manager manager;
        DnsProtocol protocol;
        int family;
        int ifindex;
        Link *link;
        DnsScope *scope;
        DnsServerType server_type;
        union in_addr_union server_addr;
        char *server_name;
        uint16_t server_port;
        DnsServer *server;
        size_t n_search_domains;
        DnsSearchDomain *search_domains[4];
} GoEnvironment;

static void go_env_teardown(GoEnvironment *env) {
        ASSERT_NOT_NULL(env);

        for (size_t i = 0 ; i < env->n_search_domains; i++)
                dns_search_domain_unref(env->search_domains[i]);

        dns_server_unref(env->server);
        dns_server_unref(env->server);
        free(env->server_name);
        dns_scope_free(env->scope);
        sd_event_unref(env->manager.event);
}

static const char *SEARCH_DOMAINS[] = { "local", "example.com", "org", "edu" };

static void go_env_setup(GoEnvironment *env, GoConfig *cfg) {
        ASSERT_NOT_NULL(env);
        ASSERT_NOT_NULL(cfg);

        env->manager = (Manager) {};
        env->protocol = DNS_PROTOCOL_DNS;
        env->family = AF_INET;

        ASSERT_OK(sd_event_new(&env->manager.event));
        ASSERT_NOT_NULL(env->manager.event);

        if (cfg->use_link) {
                env->ifindex = 1;
                ASSERT_OK(link_new(&env->manager, &env->link, env->ifindex));
                ASSERT_NOT_NULL(env->link);
                env->server_type = DNS_SERVER_LINK;
        } else {
                env->ifindex = 0;
                env->link = NULL;
                env->server_type = DNS_SERVER_FALLBACK;
        }

        if (cfg->has_scope) {
                ASSERT_OK(dns_scope_new(&env->manager, &env->scope, env->link, env->protocol, env->family));
                ASSERT_NOT_NULL(env->scope);

                env->server_addr.in.s_addr = htobe32(0x7f000001);
                env->server_name = checked_strdup("localhost");
                env->server_port = 53;

                ASSERT_OK(dns_server_new(&env->manager, &env->server, env->server_type,
                                env->link, env->family, &env->server_addr, env->server_port,
                                env->ifindex, env->server_name, RESOLVE_CONFIG_SOURCE_DBUS));

                ASSERT_NOT_NULL(env->server);
        } else {
                env->scope = NULL;
                env->server_name = NULL;
                env->server = NULL;
        }

        env->n_search_domains = cfg->n_search_domains;

        for (size_t i = 0 ; i < env->n_search_domains; i++) {
                DnsSearchDomainType type = (env->link == NULL) ? DNS_SEARCH_DOMAIN_SYSTEM : DNS_SEARCH_DOMAIN_LINK;
                ASSERT_OK(dns_search_domain_new(&env->manager, &env->search_domains[i], type, env->link, SEARCH_DOMAINS[i]));
                ASSERT_NOT_NULL(env->search_domains[i]);
        }
}

static void exercise_dns_query_go(GoConfig *cfg, void (*check_query)(DnsQuery *query)) {
        _cleanup_(go_env_teardown) GoEnvironment env = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        go_env_setup(&env, cfg);

        int flags = SD_RESOLVED_FLAGS_MAKE(env.protocol, env.family, false, false);

        if (cfg->n_search_domains > 0) {
                /* search domains trigger on single-label domains */
                ASSERT_OK(dns_question_new_address(&question, env.family, "berlin", false));
                flags &= ~SD_RESOLVED_NO_SEARCH;
        } else {
                ASSERT_OK(dns_question_new_address(&question, env.family, "www.example.com", false));
        }

        ASSERT_NOT_NULL(question);

        if (cfg->use_bypass) {
                ASSERT_OK(dns_packet_new_query(&packet, env.protocol, 0, false));
                ASSERT_NOT_NULL(packet);
                DNS_PACKET_HEADER(packet)->qdcount = htobe16(1);
                packet->question = dns_question_ref(question);
                ASSERT_OK(dns_packet_append_question(packet, question));

                /* search domains must be turned off for bypass queries, otherwise dns_query_add_candidate()
                 * tries to extract the domain name from question_idna which cannot exist on bypasses. */
                flags |= SD_RESOLVED_NO_SEARCH;
                ASSERT_OK(dns_query_new(&env.manager, &query, NULL, NULL, packet, env.ifindex, flags));
        } else {
                ASSERT_OK(dns_query_new(&env.manager, &query, question, question, NULL, env.ifindex, flags));
        }

        ASSERT_NOT_NULL(query);
        ASSERT_TRUE(dns_query_go(query));

        if (check_query != NULL)
                check_query(query);
}

static void check_query_no_servers(DnsQuery *query) {
        ASSERT_NOT_NULL(query);

        ASSERT_EQ(dns_answer_size(query->answer), 0u);
        ASSERT_EQ(query->answer_rcode, DNS_RCODE_SUCCESS);
}

TEST(dns_query_go) {
        GoConfig cfg;

        cfg = mk_go_config();
        exercise_dns_query_go(&cfg, NULL);

        cfg = mk_go_config();
        cfg.use_link = true;
        exercise_dns_query_go(&cfg, NULL);

        cfg = mk_go_config();
        cfg.use_bypass = true;
        exercise_dns_query_go(&cfg, NULL);

        cfg = mk_go_config();
        cfg.has_scope = false;
        exercise_dns_query_go(&cfg, check_query_no_servers);

        cfg = mk_go_config();
        cfg.n_search_domains = 2;
        exercise_dns_query_go(&cfg, NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
