/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-synthesize.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * dns_synthesize_answer()
 * ================================================================ */

TEST(dns_synthesize_answer_empty) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_OK(dns_question_add(question, key, 0));

        answer = dns_answer_new(0);
        ASSERT_FALSE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_reverse) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "127.0.0.0.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        answer = dns_answer_new(0);
        ASSERT_ERROR(dns_synthesize_answer(&manager, question, 0, &answer), ENXIO);
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_localhost) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
        rr->a.in_addr.s_addr = htobe32(0x7f000001);

        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_own_hostname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "resolver.local");
        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "resolver.local");
        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_gateway) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_gateway");
        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "_gateway");
        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_outbound) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_outbound");
        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "_outbound");
        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_stub) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
        ASSERT_TRUE(dns_answer_match_key(answer, rr->key, NULL));
}

TEST(dns_synthesize_answer_localhost_ptr) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("localhost");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_address) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "0.1.254.169.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        answer = dns_answer_new(0);
        ASSERT_FALSE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_TRUE(dns_answer_isempty(answer));
}

TEST(dns_synthesize_answer_address_local_hostname) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 4u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("resolver.local");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("llmnr.resolver.local");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("mdns.resolver.local");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("localhost");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
        dns_resource_record_unref(rr);
}

TEST(dns_synthesize_answer_address_local_dns_stub) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("_localdnsstub");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

TEST(dns_synthesize_answer_address_local_dns_proxy) {
        Manager manager = {};
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        question = dns_question_new(1);
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
        ASSERT_OK(dns_question_add(question, key, 0));

        manager.full_hostname = (char *)"resolver.local";
        manager.llmnr_hostname = (char *)"llmnr.resolver.local";
        manager.mdns_hostname = (char *)"mdns.resolver.local";

        ASSERT_TRUE(dns_synthesize_answer(&manager, question, 0, &answer));
        ASSERT_EQ(dns_answer_size(answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
        rr->ptr.name = strdup("_localdnsproxy");
        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
