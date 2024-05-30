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
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);

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
        ASSERT_NOT_NULL(question);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);

        ASSERT_OK(dns_question_add(question, key, 0));

        ASSERT_TRUE(dns_question_contains_key(question, key));

        assert(dns_question_size(question) == 1);
        assert(dns_question_isempty(question) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
