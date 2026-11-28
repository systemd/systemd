/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "hashmap.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-transaction.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "set.h"
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        dns_resource_key_unref(key);

        ASSERT_OK(dns_query_new(&manager, &query, question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "ns2.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        dns_resource_key_unref(key);

        ASSERT_ERROR(dns_query_new(&manager, &query, question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0), EINVAL);
        ASSERT_NULL(query);
}

#if HAVE_LIBIDN2
TEST(dns_query_new_same_utf8_and_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x98\xB1.com", /* convert_idna= */ true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_different_utf8_and_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", /* convert_idna= */ true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);
}
#endif

TEST(dns_query_new_bypass_ok) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_packet_append_question(packet, question));
        DNS_PACKET_HEADER(packet)->qdcount = htobe16(dns_question_size(question));
        ASSERT_OK(dns_packet_extract(packet));

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, /* question_idna= */ NULL, packet, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);
}

TEST(dns_query_new_bypass_conflict) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL, *extra_q = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_packet_append_question(packet, question));
        DNS_PACKET_HEADER(packet)->qdcount = htobe16(dns_question_size(question));
        ASSERT_OK(dns_packet_extract(packet));

        ASSERT_OK(dns_question_new_address(&extra_q, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(extra_q);

        ASSERT_ERROR(dns_query_new(&manager, &query, extra_q, /* question_idna= */ NULL, packet, 1, /* flags= */ 0), EINVAL);
        ASSERT_NULL(query);
}

#define MAX_QUERIES 2048

TEST(dns_query_new_too_many_questions) {
        Manager manager = {};
        DnsQuestion *question = NULL;
        DnsQuery *queries[MAX_QUERIES + 1];

        for (size_t i = 0; i < MAX_QUERIES; i++) {
                ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
                ASSERT_NOT_NULL(question);

                ASSERT_OK(dns_query_new(&manager, &queries[i], question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
                ASSERT_NOT_NULL(queries[i]);

                dns_question_unref(question);
        }

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_ERROR(dns_query_new(&manager, &queries[MAX_QUERIES], question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0), EBUSY);
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

        ASSERT_OK(dns_question_new_address(&qn1, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(qn1);
        ASSERT_OK(dns_query_new(&manager, &q1, qn1, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(q1);

        ASSERT_OK(dns_question_new_address(&qn2, AF_INET, "www.example.net", /* convert_idna= */ false));
        ASSERT_NOT_NULL(qn2);
        ASSERT_OK(dns_query_new(&manager, &q2, qn2, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(q2);

        ASSERT_OK(dns_question_new_address(&qn3, AF_INET, "www.example.org", /* convert_idna= */ false));
        ASSERT_NOT_NULL(qn3);
        ASSERT_OK(dns_query_new(&manager, &q3, qn3, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_MATCH);
}

TEST(dns_query_process_cname_one_success_exact_match) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_MATCH);

        ASSERT_EQ(query->n_cname_redirects, 0u);
}

TEST(dns_query_process_cname_one_success_no_match) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

#if HAVE_LIBIDN2
TEST(dns_query_process_cname_one_success_match_dname_utf8_same) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *q_utf8 = NULL, *q_idna = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        DnsResourceRecord *rr = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.xn--tl8h.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", /* convert_idna= */ true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

        ASSERT_OK(dns_question_new_address(&q_utf8, AF_INET, "www.\xF0\x9F\x98\xB1.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(q_utf8);

        ASSERT_OK(dns_question_new_address(&q_idna, AF_INET, "www.\xF0\x9F\x8E\xBC.com", /* convert_idna= */ true));
        ASSERT_NOT_NULL(q_idna);

        ASSERT_OK(dns_query_new(&manager, &query, q_utf8, q_idna, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_query_process_cname_one(query), DNS_QUERY_CNAME);

        ASSERT_EQ(query->n_cname_redirects, 1u);

        ASSERT_EQ(dns_question_size(query->collected_questions), 2u);
        ASSERT_EQ(dns_question_size(query->question_utf8), 1u);
        ASSERT_EQ(dns_question_size(query->question_idna), 1u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\xF0\x9F\x98\xB1.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.xn--tl8h.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->collected_questions, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\xF0\x9F\x98\xB1.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(query->question_utf8, key));
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("tmp1.example.com");
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp2.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("example.com");
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp1.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = checked_strdup("tmp2.example.com");
        dns_answer_add(query->answer, rr, 1, /* flags= */ 0, /* rrsig= */ NULL);
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

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "utf8.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "utf8.example.com");
}

TEST(dns_query_string_question_idna) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "idna.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, question, /* question_bypass= */ NULL, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "idna.example.com");
}

TEST(dns_query_string_question_bypass) {
        Manager manager = {};
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket * packet = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));
        ASSERT_NOT_NULL(packet);

        ASSERT_OK(dns_question_new_address(&packet->question, AF_INET, "bypass.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(packet->question);

        ASSERT_OK(dns_query_new(&manager, &query, /* question_utf8= */ NULL, /* question_idna= */ NULL, packet, 1, /* flags= */ 0));
        ASSERT_NOT_NULL(query);

        const char *str = dns_query_string(query);
        ASSERT_STREQ(str, "bypass.example.com");
}

TEST(dns_query_string_request_address) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna= */ false));
        ASSERT_NOT_NULL(question);

        ASSERT_OK(dns_query_new(&manager, &query, question, /* question_idna= */ NULL, /* question_bypass= */ NULL, 1, /* flags= */ 0));
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
 *   may be symlinked to a systemd resource. Ideally we could test this without accessing global files.
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
                ASSERT_OK(dns_scope_new(&env->manager, &env->scope, env->link ? DNS_SCOPE_LINK : DNS_SCOPE_GLOBAL, env->link, /* delegate= */ NULL, env->protocol, env->family));
                ASSERT_NOT_NULL(env->scope);

                env->server_addr.in.s_addr = htobe32(0x7f000001);
                env->server_name = checked_strdup("localhost");
                env->server_port = 53;

                ASSERT_OK(dns_server_new(&env->manager, &env->server, env->server_type,
                                         env->link, /* delegate= */ NULL, env->family, &env->server_addr, env->server_port,
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
                ASSERT_OK(dns_search_domain_new(&env->manager, &env->search_domains[i], type, env->link, /* delegate= */ NULL, SEARCH_DOMAINS[i]));
                ASSERT_NOT_NULL(env->search_domains[i]);
        }
}

static void exercise_dns_query_go(GoConfig *cfg, void (*check_query)(DnsQuery *query)) {
        _cleanup_(go_env_teardown) GoEnvironment env = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = NULL;

        go_env_setup(&env, cfg);

        int flags = SD_RESOLVED_FLAGS_MAKE(env.protocol, env.family, /* authenticated= */ false, /* confidential= */ false);

        if (cfg->n_search_domains > 0) {
                /* search domains trigger on single-label domains */
                ASSERT_OK(dns_question_new_address(&question, env.family, "berlin", /* convert_idna= */ false));
                flags &= ~SD_RESOLVED_NO_SEARCH;
        } else {
                ASSERT_OK(dns_question_new_address(&question, env.family, "www.example.com", /* convert_idna= */ false));
        }

        ASSERT_NOT_NULL(question);

        if (cfg->use_bypass) {
                ASSERT_OK(dns_packet_new_query(&packet, env.protocol, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));
                ASSERT_NOT_NULL(packet);
                DNS_PACKET_HEADER(packet)->qdcount = htobe16(1);
                packet->question = dns_question_ref(question);
                ASSERT_OK(dns_packet_append_question(packet, question));

                /* search domains must be turned off for bypass queries, otherwise dns_query_add_candidate()
                 * tries to extract the domain name from question_idna which cannot exist on bypasses. */
                flags |= SD_RESOLVED_NO_SEARCH;
                ASSERT_OK(dns_query_new(&env.manager, &query, /* question_utf8= */ NULL, /* question_idna= */ NULL, packet, env.ifindex, flags));
        } else {
                ASSERT_OK(dns_query_new(&env.manager, &query, question, question, /* question_bypass= */ NULL, env.ifindex, flags));
        }

        ASSERT_NOT_NULL(query);
        ASSERT_TRUE(dns_query_go(query));

        if (check_query)
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
        exercise_dns_query_go(&cfg, /* check_query= */ NULL);

        cfg = mk_go_config();
        cfg.use_link = true;
        exercise_dns_query_go(&cfg, /* check_query= */ NULL);

        cfg = mk_go_config();
        cfg.use_bypass = true;
        exercise_dns_query_go(&cfg, /* check_query= */ NULL);

        cfg = mk_go_config();
        cfg.has_scope = false;
        exercise_dns_query_go(&cfg, check_query_no_servers);

        cfg = mk_go_config();
        cfg.n_search_domains = 2;
        exercise_dns_query_go(&cfg, /* check_query= */ NULL);
}

/* ================================================================
 * The scope chain: priority levels, staggering, the authority hold and fall-through
 * ================================================================ */

/* These tests let dns_query_go() start real transactions against 127.0.0.1, then disable their I/O and
 * timers right away, and decide their outcome by setting their state directly before calling
 * dns_query_ready(), as dns_query_candidate_notify() would. The event loop then only runs the query's own
 * stagger and hold timers. */

#define CHAIN_LINKS_MAX 3

typedef struct ChainEnvironment {
        Manager manager;
        Link *links[CHAIN_LINKS_MAX];
        size_t n_links;
        DnsQuery *query;
} ChainEnvironment;

static void chain_env_teardown(ChainEnvironment *env) {
        assert(env);

        env->query = dns_query_free(env->query);
        env->manager.links = hashmap_free(env->manager.links);
        sd_event_unref(env->manager.event);
}

static void chain_env_setup(ChainEnvironment *env) {
        assert(env);

        *env = (ChainEnvironment) {
                .manager = {
                        .priority = DNS_PRIORITY_UNSET,
                        .priority_stagger_usec = PRIORITY_STAGGER_USEC_MAX,
                        .priority_hold_usec = PRIORITY_HOLD_USEC_MAX,
                },
        };

        ASSERT_OK(sd_event_new(&env->manager.event));
}

static Link* chain_env_add_link(ChainEnvironment *env, int priority, const char *route_domain) {
        union in_addr_union address = { .in.s_addr = htobe32(INADDR_LOOPBACK) };
        DnsServer *server;
        DnsScope *scope;
        Link *link;

        assert(env);
        ASSERT_LT(env->n_links, (size_t) CHAIN_LINKS_MAX);

        int ifindex = (int) ++env->n_links;

        ASSERT_OK(link_new(&env->manager, &link, ifindex));
        link->default_route = !route_domain;
        link->priority = priority;
        link->mtu = 1500; /* bytes, so that queries go via UDP rather than TCP */

        ASSERT_OK(dns_scope_new(&env->manager, &scope, DNS_SCOPE_LINK, link, /* delegate= */ NULL,
                                DNS_PROTOCOL_DNS, AF_INET));
        link->unicast_scope = scope;

        ASSERT_OK(dns_server_new(&env->manager, &server, DNS_SERVER_LINK, link, /* delegate= */ NULL,
                                 AF_INET, &address, 53, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        if (route_domain) {
                DnsSearchDomain *d; /* owned by the link's list */

                ASSERT_OK(dns_search_domain_new(&env->manager, &d, DNS_SEARCH_DOMAIN_LINK, link,
                                                /* delegate= */ NULL, route_domain));
                d->route_only = true;
        }

        env->links[ifindex - 1] = link;
        return link;
}

static void chain_on_complete(DnsQuery *q) {
        /* Keep the query around, the test checks and frees it. */
}

static DnsQueryCandidate* chain_find_scope_candidate(DnsQuery *q, DnsScope *scope) {
        assert(q);
        assert(scope);

        LIST_FOREACH(candidates_by_query, c, q->candidates)
                if (c->scope == scope)
                        return c;

        return NULL;
}

static DnsQueryCandidate* chain_find_candidate(DnsQuery *q, Link *link) {
        assert(link);

        return chain_find_scope_candidate(q, link->unicast_scope);
}

static void chain_freeze(DnsQuery *q) {
        assert(q);

        /* Stop the transactions from talking to the network or timing out on their own. */
        LIST_FOREACH(candidates_by_query, c, q->candidates) {
                DnsTransaction *t;

                SET_FOREACH(t, c->transactions) {
                        (void) sd_event_source_set_enabled(t->timeout_event_source, SD_EVENT_OFF);
                        (void) sd_event_source_set_enabled(t->dns_udp_event_source, SD_EVENT_OFF);
                }
        }
}

static void chain_env_go_full(ChainEnvironment *env, uint16_t type, const char *name, uint64_t flags) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        assert(env);

        if (type == DNS_TYPE_A)
                ASSERT_OK(dns_question_new_address(&question, AF_INET, name, /* convert_idna= */ false));
        else {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(DNS_CLASS_IN, type, name);
                ASSERT_NOT_NULL(key);
                question = dns_question_new(1);
                ASSERT_NOT_NULL(question);
                ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        }
        ASSERT_OK(dns_query_new(&env->manager, &env->query, question, question, /* question_bypass= */ NULL,
                                /* ifindex= */ 0, flags));
        env->query->complete = chain_on_complete;

        ASSERT_OK_POSITIVE(dns_query_go(env->query));
        chain_freeze(env->query);
}

static void chain_env_go(ChainEnvironment *env) {
        chain_env_go_full(env, DNS_TYPE_A, "www.example.com",
                          SD_RESOLVED_FLAGS_MAKE(DNS_PROTOCOL_DNS, AF_INET, /* authenticated= */ false,
                                                 /* confidential= */ false));
}

static Link* chain_env_add_llmnr_link(ChainEnvironment *env) {
        DnsScope *scope;
        Link *link;

        assert(env);
        ASSERT_LT(env->n_links, (size_t) CHAIN_LINKS_MAX);

        int ifindex = (int) ++env->n_links;

        /* A link with LLMNR only, and no DNS servers. */
        ASSERT_OK(link_new(&env->manager, &link, ifindex));
        link->mtu = 1500; /* bytes */

        ASSERT_OK(dns_scope_new(&env->manager, &scope, DNS_SCOPE_LINK, link, /* delegate= */ NULL,
                                DNS_PROTOCOL_LLMNR, AF_INET));
        link->llmnr_ipv4_scope = scope;

        env->links[ifindex - 1] = link;
        return link;
}

static void chain_run_timer(ChainEnvironment *env) {
        assert(env);

        unsigned n_levels = env->query->n_levels;

        /* Run the event loop until the query's stagger or hold timer fired, i.e. until a level was added
         * or the query completed. The transactions are frozen and the query timeout is 120 s away, so
         * nothing else can make progress. Other events, such as closing sockets of the manager's
         * graveyard, may be dispatched first. */
        for (unsigned i = 0; i < 16; i++) {
                ASSERT_OK(sd_event_run(env->manager.event, PRIORITY_STAGGER_USEC_MAX + PRIORITY_HOLD_USEC_MAX));
                chain_freeze(env->query);

                if (env->query->n_levels != n_levels || !DNS_TRANSACTION_IS_LIVE(env->query->state))
                        return;
        }

        assert_not_reached();
}

static void chain_fail_scope(DnsQuery *q, DnsScope *scope, DnsTransactionState state, int rcode, bool authenticated) {
        DnsQueryCandidate *c = chain_find_scope_candidate(q, scope);
        DnsTransaction *t;

        ASSERT_NOT_NULL(c);

        SET_FOREACH(t, c->transactions) {
                t->state = state;
                t->answer_rcode = rcode;
                t->answer_source = DNS_TRANSACTION_NETWORK;
                SET_FLAG(t->answer_query_flags, SD_RESOLVED_AUTHENTICATED, authenticated);
        }
}

static void chain_fail(DnsQuery *q, Link *link, DnsTransactionState state, int rcode, bool authenticated) {
        assert(link);

        chain_fail_scope(q, link->unicast_scope, state, rcode, authenticated);
}

static DnsResourceRecord* chain_record(Link *link) {
        DnsResourceRecord *rr;

        assert(link);

        union in_addr_union address = { .in.s_addr = htobe32(0xc0000200 + link->ifindex) };

        ASSERT_OK(dns_resource_record_new_address(&rr, AF_INET, &address, "www.example.com"));
        return rr;
}

static void chain_succeed(DnsQuery *q, Link *link) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = chain_record(link);
        DnsQueryCandidate *c = chain_find_candidate(q, link);
        DnsTransaction *t;

        ASSERT_NOT_NULL(c);

        SET_FOREACH(t, c->transactions) {
                t->state = DNS_TRANSACTION_SUCCESS;
                t->answer_rcode = DNS_RCODE_SUCCESS;
                t->answer_source = DNS_TRANSACTION_NETWORK;

                dns_answer_unref(t->answer);
                t->answer = dns_answer_new(1);
                ASSERT_NOT_NULL(t->answer);
                ASSERT_OK(dns_answer_add(t->answer, rr, link->ifindex, /* flags= */ 0, /* rrsig= */ NULL));
        }
}

static void chain_assert_answer_from(DnsQuery *q, Link *link) {
        assert(q);

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = chain_record(link);

        ASSERT_EQ(q->state, DNS_TRANSACTION_SUCCESS);
        ASSERT_TRUE(dns_answer_contains(q->answer, rr));
}

static bool chain_stagger_armed(DnsQuery *q) {
        assert(q);

        return sd_event_source_get_enabled(q->stagger_event_source, /* ret= */ NULL) > 0;
}

TEST(dns_query_chain_without_priorities) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *a, *b;

        chain_env_setup(&env);
        a = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        b = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        chain_env_go(&env);

        /* Without priorities, every scope is asked at once, as before. */
        ASSERT_EQ(env.query->n_levels, 1u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, a));
        ASSERT_NOT_NULL(chain_find_candidate(env.query, b));
        ASSERT_FALSE(chain_stagger_armed(env.query));

        chain_fail(env.query, a, DNS_TRANSACTION_TIMEOUT, /* rcode= */ 0, /* authenticated= */ false);
        dns_query_ready(env.query);
        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);

        chain_succeed(env.query, b);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, b);
}

TEST(dns_query_chain_failure_starts_next_level) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *first, *unset, *second;

        chain_env_setup(&env);
        second = chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        first = chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        unset = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        chain_env_go(&env);

        /* The lowest priority goes first, and scopes without a priority join it. */
        ASSERT_EQ(env.query->n_levels, 1u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, first));
        ASSERT_NOT_NULL(chain_find_candidate(env.query, unset));
        ASSERT_NULL(chain_find_candidate(env.query, second));
        ASSERT_TRUE(chain_stagger_armed(env.query));

        /* An unauthenticated NXDOMAIN is a failure, and does not end the chain. */
        chain_fail(env.query, first, DNS_TRANSACTION_TIMEOUT, /* rcode= */ 0, /* authenticated= */ false);
        chain_fail(env.query, unset, DNS_TRANSACTION_RCODE_FAILURE, DNS_RCODE_NXDOMAIN, /* authenticated= */ false);
        dns_query_ready(env.query);
        chain_freeze(env.query);

        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);
        ASSERT_EQ(env.query->n_levels, 2u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, second));
        ASSERT_FALSE(chain_stagger_armed(env.query));

        chain_succeed(env.query, second);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, second);
}

TEST(dns_query_chain_last_failure_returned) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *first, *second;

        chain_env_setup(&env);
        first = chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        second = chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        chain_env_go(&env);

        chain_fail(env.query, first, DNS_TRANSACTION_TIMEOUT, /* rcode= */ 0, /* authenticated= */ false);
        dns_query_ready(env.query);
        chain_freeze(env.query);

        chain_fail(env.query, second, DNS_TRANSACTION_RCODE_FAILURE, DNS_RCODE_SERVFAIL, /* authenticated= */ false);
        dns_query_ready(env.query);

        ASSERT_EQ(env.query->state, DNS_TRANSACTION_RCODE_FAILURE);
        ASSERT_EQ(env.query->answer_rcode, DNS_RCODE_SERVFAIL);
}

TEST(dns_query_chain_validated_nxdomain_ends_chain) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *first;

        chain_env_setup(&env);
        first = chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        (void) chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        chain_env_go(&env);

        chain_fail(env.query, first, DNS_TRANSACTION_RCODE_FAILURE, DNS_RCODE_NXDOMAIN, /* authenticated= */ true);
        dns_query_ready(env.query);

        ASSERT_EQ(env.query->state, DNS_TRANSACTION_RCODE_FAILURE);
        ASSERT_EQ(env.query->answer_rcode, DNS_RCODE_NXDOMAIN);
        ASSERT_EQ(env.query->n_levels, 1u);
}

TEST(dns_query_chain_stagger_and_hold) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *first, *second;

        chain_env_setup(&env);
        env.manager.priority_stagger_usec = PRIORITY_STAGGER_USEC_MIN;
        first = chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        second = chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        chain_env_go(&env);

        /* The first level is slow: the stagger delay starts the second one. */
        chain_run_timer(&env);
        ASSERT_EQ(env.query->n_levels, 2u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, second));

        /* The second level answers first: its answer waits for the first level. */
        chain_succeed(env.query, second);
        dns_query_ready(env.query);
        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);
        ASSERT_GT(sd_event_source_get_enabled(env.query->hold_event_source, /* ret= */ NULL), 0);

        /* The first level answers within the hold, and wins. */
        chain_succeed(env.query, first);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, first);
}

TEST(dns_query_chain_hold_expires) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *second;

        chain_env_setup(&env);
        env.manager.priority_stagger_usec = PRIORITY_STAGGER_USEC_MIN;
        env.manager.priority_hold_usec = PRIORITY_STAGGER_USEC_MIN;
        (void) chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        second = chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        chain_env_go(&env);

        chain_run_timer(&env);
        ASSERT_EQ(env.query->n_levels, 2u);

        chain_succeed(env.query, second);
        dns_query_ready(env.query);
        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);

        /* The first level stays silent: the later answer is used once the hold expires. */
        chain_run_timer(&env);
        chain_assert_answer_from(env.query, second);
}

TEST(dns_query_chain_no_hold) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *second;

        chain_env_setup(&env);
        env.manager.priority_stagger_usec = PRIORITY_STAGGER_USEC_MIN;
        env.manager.priority_hold_usec = 0;
        (void) chain_env_add_link(&env, 10, /* route_domain= */ NULL);
        second = chain_env_add_link(&env, 20, /* route_domain= */ NULL);
        chain_env_go(&env);

        chain_run_timer(&env);

        /* PriorityHoldSec=0 takes the first success, like plain Happy Eyeballs. */
        chain_succeed(env.query, second);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, second);
}

static void exercise_chain_fallthrough(bool fallthrough) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *specific, *general;

        chain_env_setup(&env);
        env.manager.priority_stagger_usec = PRIORITY_STAGGER_USEC_MIN;
        specific = chain_env_add_link(&env, DNS_PRIORITY_UNSET, "example.com");
        specific->fallthrough = fallthrough;
        general = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        chain_env_go(&env);

        /* The routing domain wins outright, and the stagger never crosses to less specific scopes. */
        ASSERT_EQ(env.query->n_levels, 1u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, specific));
        ASSERT_NULL(chain_find_candidate(env.query, general));
        ASSERT_FALSE(chain_stagger_armed(env.query));

        chain_fail(env.query, specific, DNS_TRANSACTION_RCODE_FAILURE, DNS_RCODE_SERVFAIL, /* authenticated= */ false);
        dns_query_ready(env.query);

        if (!fallthrough) {
                ASSERT_EQ(env.query->state, DNS_TRANSACTION_RCODE_FAILURE);
                ASSERT_EQ(env.query->n_levels, 1u);
                return;
        }

        chain_freeze(env.query);
        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);
        ASSERT_EQ(env.query->n_levels, 2u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, general));

        chain_succeed(env.query, general);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, general);
}

TEST(dns_query_chain_fallthrough) {
        exercise_chain_fallthrough(/* fallthrough= */ false);
        exercise_chain_fallthrough(/* fallthrough= */ true);
}

TEST(dns_query_chain_fallthrough_llmnr_abstains) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *search, *llmnr, *general;
        DnsSearchDomain *d; /* owned by the link's list */

        chain_env_setup(&env);

        /* A single-label name puts a DNS scope with a search domain and an LLMNR scope in the same tier.
         * TXT, since unicast DNS refuses single-label A and AAAA lookups unless ResolveUnicastSingleLabel=
         * is set. */
        search = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        search->default_route = false;
        search->fallthrough = true;
        ASSERT_OK(dns_search_domain_new(&env.manager, &d, DNS_SEARCH_DOMAIN_LINK, search,
                                        /* delegate= */ NULL, "example.com"));
        llmnr = chain_env_add_llmnr_link(&env);
        general = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);

        chain_env_go_full(&env, DNS_TYPE_TXT, "berlin", SD_RESOLVED_DNS|SD_RESOLVED_LLMNR_IPV4);

        ASSERT_EQ(env.query->n_levels, 1u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, search));
        ASSERT_NOT_NULL(chain_find_scope_candidate(env.query, llmnr->llmnr_ipv4_scope));
        ASSERT_NULL(chain_find_candidate(env.query, general));

        /* The LLMNR scope has no fall-through setting of its own, and does not prevent it. */
        chain_fail(env.query, search, DNS_TRANSACTION_RCODE_FAILURE, DNS_RCODE_SERVFAIL, /* authenticated= */ false);
        chain_fail_scope(env.query, llmnr->llmnr_ipv4_scope, DNS_TRANSACTION_TIMEOUT, /* rcode= */ 0, /* authenticated= */ false);
        dns_query_ready(env.query);
        chain_freeze(env.query);

        ASSERT_EQ(env.query->state, DNS_TRANSACTION_PENDING);
        ASSERT_EQ(env.query->n_levels, 2u);
        ASSERT_NOT_NULL(chain_find_candidate(env.query, general));

        chain_succeed(env.query, general);
        dns_query_ready(env.query);
        chain_assert_answer_from(env.query, general);
}

TEST(dns_query_chain_llmnr_only_tier_does_not_fall_through) {
        _cleanup_(chain_env_teardown) ChainEnvironment env;
        Link *llmnr, *general;

        chain_env_setup(&env);
        llmnr = chain_env_add_llmnr_link(&env);
        general = chain_env_add_link(&env, DNS_PRIORITY_UNSET, /* route_domain= */ NULL);
        general->fallthrough = true;

        chain_env_go_full(&env, DNS_TYPE_TXT, "berlin", SD_RESOLVED_DNS|SD_RESOLVED_LLMNR_IPV4);

        /* The default-route DNS scope would be the next tier for this name, and would look up a TXT record
         * for it, ... */
        ASSERT_EQ(dns_scope_good_domain(general->unicast_scope, env.query, env.query->flags), DNS_SCOPE_MAYBE);
        ASSERT_EQ(env.query->n_levels, 1u);
        ASSERT_NOT_NULL(chain_find_scope_candidate(env.query, llmnr->llmnr_ipv4_scope));
        ASSERT_NULL(chain_find_candidate(env.query, general));

        /* ... but a name only LLMNR was asked for never goes to unicast DNS. */
        chain_fail_scope(env.query, llmnr->llmnr_ipv4_scope, DNS_TRANSACTION_TIMEOUT, /* rcode= */ 0, /* authenticated= */ false);
        dns_query_ready(env.query);

        ASSERT_EQ(env.query->state, DNS_TRANSACTION_TIMEOUT);
        ASSERT_EQ(env.query->n_levels, 1u);
}

static int intro(void) {
        /* Disable hooks in order to make test cases hermetic */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_RESOLVED_HOOK", "0", /* overwrite= */ false));
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
