/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "in-addr-util.h"
#include "memstream-util.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"
#include "tests.h"

/* ================================================================
 * dns_question_add()
 * ================================================================ */

TEST(dns_question_add) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));

        /* NULL question */
        ASSERT_EQ(dns_question_size(question), 0u);
        ASSERT_TRUE(dns_question_isempty(question));

        /* zero-size question */
        ASSERT_NOT_NULL(question = dns_question_new(0));
        ASSERT_ERROR(dns_question_add(question, key, /* flags = */ 0), ENOSPC);
        ASSERT_OK_ZERO(dns_question_contains_key(question, key));
        ASSERT_EQ(dns_question_size(question), 0u);
        ASSERT_TRUE(dns_question_isempty(question));
        question = dns_question_unref(question);

        /* single question */
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_FALSE(dns_question_isempty(question));
}

/* ================================================================
 * dns_question_new_address()
 * ================================================================ */

TEST(dns_question_new_address) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key4 = NULL, *key6 = NULL;

        ASSERT_NOT_NULL(key4 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_NOT_NULL(key6 = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com"));

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", 0));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key4));
        ASSERT_OK_ZERO(dns_question_contains_key(question, key6));
        question = dns_question_unref(question);

        ASSERT_OK(dns_question_new_address(&question, AF_INET6, "www.example.com", 0));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_OK_ZERO(dns_question_contains_key(question, key4));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key6));
}

#if HAVE_LIBIDN || HAVE_LIBIDN2
TEST(dns_question_new_address_convert_idna) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.\xF0\x9F\x98\xB1.com", 1));
        ASSERT_NOT_NULL(question);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.xn--s38h.com"));

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));
}
#endif

/* ================================================================
 * dns_question_new_reverse()
 * ================================================================ */

TEST(dns_question_new_reverse) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        union in_addr_union addr = { .in.s_addr = htobe32(0xc0a8017f) };

        ASSERT_OK(dns_question_new_reverse(&question, AF_INET, &addr));
        ASSERT_NOT_NULL(question);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "127.1.168.192.in-addr.arpa"));

        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));
}

/* ================================================================
 * dns_question_new_service()
 * ================================================================ */

TEST(dns_question_new_service) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        /* no domain */
        ASSERT_ERROR(dns_question_new_service(
                                     &question,
                                     /* service = */ NULL,
                                     "_xmpp._tcp",
                                     /* domain = */ NULL,
                                     /* with_txt = */ false,
                                     /* convert_idna = */ false), EINVAL);
        ASSERT_NULL(question);

        /* domain only */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  /* service = */ NULL,
                                  /* type = */ NULL,
                                  "www.example.com",
                                  /* with_txt = */ false,
                                  /* convert_idna = */ false));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* convert idna without type -> ignored */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  /* service = */ NULL,
                                  /* type = */ NULL,
                                  "\xF0\x9F\x98\xB1.com",
                                  /* with_txt = */ false,
                                  /* convert_idna = */ true));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "\xF0\x9F\x98\xB1.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* with type */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  /* service = */ NULL,
                                  "_xmpp._tcp",
                                  "example.com",
                                  /* with_txt = */ false,
                                  /* convert_idna = */ false));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.example.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

#if HAVE_LIBIDN || HAVE_LIBIDN2
        /* convert idna with type */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  /* service = */ NULL,
                                  "_xmpp._tcp",
                                  "\xF0\x9F\x98\xB1.com",
                                  /* with_txt = */ false,
                                  /* convert_idna = */ true));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.xn--s38h.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* with txt */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  /* service = */ NULL,
                                  "_xmpp._tcp",
                                  "\xF0\x9F\x98\xB1.com",
                                  /* with_txt = */ true,
                                  /* convert_idna = */ true));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 2u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "_xmpp._tcp.xn--s38h.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));
        dns_resource_key_unref(key);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, "_xmpp._tcp.xn--s38h.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);
#endif

        /* invalid type */
        ASSERT_ERROR(dns_question_new_service(
                                     &question,
                                     /* service = */ NULL,
                                     "_xmpp.tcp",
                                     "example.com",
                                     /* with_txt = */ false,
                                     /* convert_idna = */ false), EINVAL);
        ASSERT_NULL(question);

        /* invalid type (too short) */
        ASSERT_ERROR(dns_question_new_service(
                                     &question,
                                     /* service = */ NULL,
                                     "_xmpp",
                                     "example.com",
                                     /* with_txt = */ false,
                                     /* convert_idna = */ false), EINVAL);
        ASSERT_NULL(question);

        /* invalid type (too long) */
        ASSERT_ERROR(dns_question_new_service(
                                     &question,
                                     /* service = */ NULL,
                                     "_xmpp._tcp._extra",
                                     "example.com",
                                     /* with_txt = */ false,
                                     /* convert_idna = */ false), EINVAL);
        ASSERT_NULL(question);

        /* with service and type */
        ASSERT_OK(dns_question_new_service(
                                  &question,
                                  "service",
                                  "_xmpp._tcp",
                                  "example.com",
                                  /* with_txt = */ false,
                                  /* convert_idna = */ false));
        ASSERT_NOT_NULL(question);
        ASSERT_EQ(dns_question_size(question), 1u);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, "service._xmpp._tcp.example.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(question, key));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* with service but without type */
        ASSERT_ERROR(dns_question_new_service(
                                     &question,
                                     "service",
                                     /* type = */ NULL,
                                     "example.com",
                                     /* with_txt = */ false,
                                     /* convert_idna = */ false), EINVAL);
        ASSERT_NULL(question);
}

/* ================================================================
 * dns_question_matches_rr()
 * ================================================================ */

TEST(dns_question_matches_rr) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsResourceKey *key;
        DnsResourceRecord *rr;

        ASSERT_NOT_NULL(question = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_question_matches_rr(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com"));
        ASSERT_OK_POSITIVE(dns_question_matches_rr(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "mail.example.com"));
        ASSERT_OK_ZERO(dns_question_matches_rr(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);
}

/* ================================================================
 * dns_question_matches_cname_or_dname()
 * ================================================================ */

TEST(dns_question_matches_cname_or_dname) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *keya = NULL, *keyc = NULL;
        DnsResourceRecord *rr;

        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_NOT_NULL(keya = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, keya, /* flags = */ 0));

        /* cname */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_question_matches_cname_or_dname(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);

        /* dname */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com"));
        ASSERT_OK_POSITIVE(dns_question_matches_cname_or_dname(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);

        /* A record -> fail */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_ZERO(dns_question_matches_cname_or_dname(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);

        dns_question_unref(question);
        ASSERT_NOT_NULL(question = dns_question_new(2));

        ASSERT_NOT_NULL(keyc = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com"));
        ASSERT_OK(dns_question_add(question, keyc, /* flags = */ 0));
        ASSERT_OK(dns_question_add(question, keya, /* flags = */ 0));

        /* refuse cname if question has cname */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_OK_ZERO(dns_question_matches_cname_or_dname(question, rr, /* search_domain = */ NULL));
        dns_resource_record_unref(rr);
}

/* ================================================================
 * dns_question_is_valid_for_query()
 * ================================================================ */

TEST(dns_question_is_valid_for_query) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        /* NULL question */
        ASSERT_OK_ZERO(dns_question_is_valid_for_query(question));

        /* empty question */
        ASSERT_NOT_NULL(question = dns_question_new(0));
        ASSERT_OK_ZERO(dns_question_is_valid_for_query(question));

        question = dns_question_unref(question);

        /* single key */
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        ASSERT_OK_POSITIVE(dns_question_is_valid_for_query(question));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* invalid type */
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_OPT, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        ASSERT_OK_ZERO(dns_question_is_valid_for_query(question));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* multiple keys with the same name */
        ASSERT_NOT_NULL(question = dns_question_new(2));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.EXAMPLE.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        ASSERT_OK_POSITIVE(dns_question_is_valid_for_query(question));

        question = dns_question_unref(question);
        key = dns_resource_key_unref(key);

        /* multiple keys with different names */
        ASSERT_NOT_NULL(question = dns_question_new(2));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.org"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        ASSERT_OK_ZERO(dns_question_is_valid_for_query(question));
}

/* ================================================================
 * dns_question_is_equal()
 * ================================================================ */

TEST(dns_question_is_equal) {
        _cleanup_(dns_question_unrefp) DnsQuestion *a = NULL, *b = NULL;
        DnsResourceKey *key;

        /* NULL */
        ASSERT_OK_POSITIVE(dns_question_is_equal(NULL, NULL));

        /* empty questions */
        ASSERT_NOT_NULL(a = dns_question_new(0));
        ASSERT_NOT_NULL(b = dns_question_new(0));
        ASSERT_OK_POSITIVE(dns_question_is_equal(a, NULL));
        ASSERT_OK_POSITIVE(dns_question_is_equal(NULL, a));
        ASSERT_OK_POSITIVE(dns_question_is_equal(a, a));
        ASSERT_OK_POSITIVE(dns_question_is_equal(a, b));

        a = dns_question_unref(a);

        /* an address question (with NULL, self, and an empty) */
        ASSERT_OK(dns_question_new_address(&a, AF_INET, "www.example.com", /* convert_idna = */ false));
        ASSERT_NOT_NULL(a);
        ASSERT_OK_ZERO(dns_question_is_equal(a, NULL));
        ASSERT_OK_ZERO(dns_question_is_equal(NULL, a));
        ASSERT_OK_POSITIVE(dns_question_is_equal(a, a));
        ASSERT_OK_ZERO(dns_question_is_equal(a, b));
        ASSERT_OK_ZERO(dns_question_is_equal(b, a));

        b = dns_question_unref(b);

        /* an address question (with same name) */
        ASSERT_OK(dns_question_new_address(&b, AF_INET, "www.EXAMPLE.com", /* convert_idna = */ false));
        ASSERT_NOT_NULL(b);
        ASSERT_OK_POSITIVE(dns_question_is_equal(a, b));
        ASSERT_OK_POSITIVE(dns_question_is_equal(b, a));

        b = dns_question_unref(b);

        /* an address question (with different name) */
        ASSERT_OK(dns_question_new_address(&b, AF_INET, "www.EXAMPLE.org", /* convert_idna = */ false));
        ASSERT_NOT_NULL(b);
        ASSERT_OK_ZERO(dns_question_is_equal(a, b));
        ASSERT_OK_ZERO(dns_question_is_equal(b, a));

        b = dns_question_unref(b);

        /* an address question (with different type) */
        ASSERT_OK(dns_question_new_address(&b, AF_INET6, "www.example.com", /* convert_idna = */ false));
        ASSERT_NOT_NULL(b);
        ASSERT_OK_ZERO(dns_question_is_equal(a, b));
        ASSERT_OK_ZERO(dns_question_is_equal(b, a));

        b = dns_question_unref(b);

        /* number of keys are different */
        ASSERT_NOT_NULL(b = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(b, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com"));
        ASSERT_OK(dns_question_add(b, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_OK_ZERO(dns_question_is_equal(a, b));
        ASSERT_OK_ZERO(dns_question_is_equal(b, a));

        a = dns_question_unref(a);

        /* same keys with different order */
        ASSERT_NOT_NULL(a = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com"));
        ASSERT_OK(dns_question_add(a, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(a, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_OK_POSITIVE(dns_question_is_equal(a, b));
        ASSERT_OK_POSITIVE(dns_question_is_equal(b, a));
}

/* ================================================================
 * dns_question_cname_redirect()
 * ================================================================ */

TEST(dns_question_cname_redirect) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL, *expected = NULL, *ret = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsResourceKey *key;

        /* prepare cname record */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"));
        rr->cname.name = strdup("example.com");

        ASSERT_OK(dns_question_new_address(&expected, AF_INET, "example.com", /* convert_idna = */ false));
        ASSERT_NOT_NULL(expected);

        /* NULL */
        ASSERT_OK_ZERO(dns_question_cname_redirect(NULL, rr, &ret));
        ASSERT_NULL(ret);

        /* an empty question */
        ASSERT_NOT_NULL(question = dns_question_new(0));
        ASSERT_OK_ZERO(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_NULL(ret);

        question = dns_question_unref(question);

        /* match cname */
        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna = */ false));
        ASSERT_OK_POSITIVE(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_OK_POSITIVE(dns_question_is_equal(ret, expected));

        question = dns_question_unref(question);
        ret = dns_question_unref(ret);

        /* same name */
        ASSERT_OK(dns_question_new_address(&question, AF_INET, "example.com", /* convert_idna = */ false));
        ASSERT_OK_ZERO(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_NULL(ret);

        question = dns_question_unref(question);

        /* no match (same domain) */
        ASSERT_OK(dns_question_new_address(&question, AF_INET, "mail.example.com", /* convert_idna = */ false));
        ASSERT_OK_POSITIVE(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_OK_POSITIVE(dns_question_is_equal(ret, expected));

        question = dns_question_unref(question);
        ret = dns_question_unref(ret);

        /* no match (different domain) */
        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.org", /* convert_idna = */ false));
        ASSERT_OK_POSITIVE(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_OK_POSITIVE(dns_question_is_equal(ret, expected));

        question = dns_question_unref(question);
        expected = dns_question_unref(expected);
        ret = dns_question_unref(ret);

        /* prepare dname record */
        dns_resource_record_unref(rr);
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com"));
        rr->dname.name = strdup("v2.example.com");

        ASSERT_OK(dns_question_new_address(&expected, AF_INET, "www.v2.example.com", /* convert_idna = */ false));

        /* match dname */
        ASSERT_OK(dns_question_new_address(&question, AF_INET, "www.example.com", /* convert_idna = */ false));
        ASSERT_OK_POSITIVE(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_OK_POSITIVE(dns_question_is_equal(ret, expected));

        question = dns_question_unref(question);
        expected = dns_question_unref(expected);
        ret = dns_question_unref(ret);

        /* multiple dname match */
        ASSERT_NOT_NULL(question = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_OK_POSITIVE(dns_question_cname_redirect(question, rr, &ret));
        ASSERT_NOT_NULL(ret);
        ASSERT_EQ(dns_question_size(ret), 2u);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.v2.example.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(ret, key));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.v2.example.com"));
        ASSERT_OK_POSITIVE(dns_question_contains_key(ret, key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_question_dump()
 * ================================================================ */

TEST(dns_question_dump) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(memstream_done) MemStream ms = {};
        _cleanup_free_ char *buf = NULL;
        FILE *f;

        ASSERT_NOT_NULL(question = dns_question_new(3));

        uint16_t type;
        FOREACH_ARGUMENT(type, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_TXT) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, type, "www.example.com"));
                ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        }

        ASSERT_EQ(dns_question_size(question), 3u);

        ASSERT_NOT_NULL(f = memstream_init(&ms));
        dns_question_dump(question, f);
        ASSERT_OK(memstream_finalize(&ms, &buf, /* ret_size = */ NULL));
        ASSERT_STREQ(buf,
                     "\twww.example.com IN A\n"
                     "\twww.example.com IN AAAA\n"
                     "\twww.example.com IN TXT\n");
}

/* ================================================================
 * dns_question_first_name()
 * ================================================================ */

TEST(dns_question_first_name) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        DnsResourceKey *key;

        /* NULL */
        ASSERT_NULL(dns_question_first_name(NULL));

        /* an empty question */
        ASSERT_NOT_NULL(question = dns_question_new(0));
        ASSERT_NULL(dns_question_first_name(question));
        question = dns_question_unref(question);

        /* multiple keys */
        ASSERT_NOT_NULL(question = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com"));
        ASSERT_OK(dns_question_add(question, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_STREQ(dns_question_first_name(question), "www.example.com");
}

/* ================================================================
 * dns_question_merge()
 * ================================================================ */

TEST(dns_question_merge_empty_first) {
        _cleanup_(dns_question_unrefp) DnsQuestion *a = NULL, *b = NULL, *ret = NULL;
        DnsResourceKey *key;

        ASSERT_NOT_NULL(a = dns_question_new(0));
        ASSERT_NOT_NULL(b = dns_question_new(0));

        /* trivial cases */
        ASSERT_OK(dns_question_merge(NULL, NULL, &ret));
        ASSERT_NULL(ret);
        ASSERT_OK(dns_question_merge(NULL, a, &ret));
        ASSERT_NULL(ret);
        ASSERT_OK(dns_question_merge(a, NULL, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(a, a, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(a, b, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);

        a = dns_question_unref(a);

        /* single question */
        ASSERT_OK(dns_question_new_address(&a, AF_INET, "www.example.com", /* convert_idna = */ false));
        ASSERT_OK(dns_question_merge(NULL, a, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(a, NULL, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(a, a, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(a, b, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);
        ASSERT_OK(dns_question_merge(b, a, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_question_unref(ret);

        b = dns_question_unref(b);

        /* multiple questions */
        ASSERT_NOT_NULL(b = dns_question_new(2));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com"));
        ASSERT_OK(dns_question_add(b, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com"));
        ASSERT_OK(dns_question_add(b, key, /* flags = */ 0));
        dns_resource_key_unref(key);

        ASSERT_OK(dns_question_merge(a, b, &ret));
        ASSERT_EQ(dns_question_size(ret), 3u);

        uint16_t types[3];
        size_t i = 0;
        DNS_QUESTION_FOREACH(key, ret)
                types[i++] = key->type;

        ASSERT_EQ(types[0], DNS_TYPE_A);
        ASSERT_EQ(types[1], DNS_TYPE_AAAA);
        ASSERT_EQ(types[2], DNS_TYPE_TXT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
