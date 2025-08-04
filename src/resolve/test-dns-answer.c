/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "memstream-util.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"
#include "strv.h"
#include "tests.h"

/* ================================================================
 * dns_answer_add()
 * ================================================================ */

TEST(dns_answer_add_a) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_TRUE(dns_answer_contains(answer, rr));
}

/* ================================================================
 * dns_answer_match_key()
 * ================================================================ */

TEST(dns_answer_match_key_single) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsResourceKey *key;
        DnsAnswerFlags flags;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_EQ(dns_answer_size(answer), 1u);

        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, rr->key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, rr->key, &flags));
        ASSERT_EQ((int)flags, DNS_ANSWER_CACHEABLE);

        /* ANY class matches */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* ANY type matches */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* non-matching type */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_OK_ZERO(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* name is case-insensitive */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "WWW.EXAMPLE.COM"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* non-matching name */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com"));
        ASSERT_OK_ZERO(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* name containing an error */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com"));
        ASSERT_ERROR(dns_answer_match_key(answer, key, /* ret_flags = */ NULL), EINVAL);
        dns_resource_key_unref(key);
}

TEST(dns_answer_match_key_multiple) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr;
        DnsResourceKey *key;
        DnsAnswerFlags flags;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_AUTHENTICATED, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_answer_size(answer), 2u);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_SECTION_ANSWER);
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_find_soa()
 * ================================================================ */

TEST(dns_answer_find_soa) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr;
        DnsResourceKey *key;
        DnsAnswerFlags flags;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_ZERO(dns_answer_find_soa(answer, key, &rr, &flags));
        dns_resource_key_unref(key);

        ASSERT_OK_POSITIVE(dns_answer_add_soa(answer, "example.com", 3600, 1));

        /* does not find SOA keys */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com"));
        ASSERT_OK_ZERO(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_NULL(rr);
        ASSERT_EQ((int) flags, 0);
        dns_resource_key_unref(key);

        /* finds matching A key */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com"));
        ASSERT_OK_POSITIVE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);

        /* finds matching A key suddomain */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "foo.www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com"));
        ASSERT_OK_POSITIVE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);

        /* does not match simple prefix */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "fooexample.com"));
        ASSERT_OK_ZERO(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_NULL(rr);
        ASSERT_EQ((int) flags, 0);
        dns_resource_key_unref(key);

        /* does not match parent domain */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "com"));
        ASSERT_OK_ZERO(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_NULL(rr);
        ASSERT_EQ((int) flags, 0);
        dns_resource_key_unref(key);

        /* returns an error for bad escapes */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com"));
        rr = POINTER_MAX;
        flags = 4321;
        ASSERT_ERROR(dns_answer_find_soa(answer, key, &rr, &flags), EINVAL);
        ASSERT_PTR_EQ(rr, POINTER_MAX);
        ASSERT_EQ((int) flags, 4321);
        dns_resource_key_unref(key);
}

TEST(dns_answer_find_soa_multi) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key;
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_OK_POSITIVE(dns_answer_add_soa(answer, "example.com", 3600, 1));
        ASSERT_OK_POSITIVE(dns_answer_add_soa(answer, "example.org", 3600, 1));

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com"));
        ASSERT_OK_POSITIVE(dns_resource_key_equal(rr->key, key));
        ASSERT_EQ((int) flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org"));
        ASSERT_OK_POSITIVE(dns_answer_find_soa(answer, key, &rr, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_AUTHENTICATED);
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.org"));
        ASSERT_OK_POSITIVE(dns_resource_key_equal(rr->key, key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_merge()
 * ================================================================ */

TEST(dns_answer_merge) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL, *ret = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        ASSERT_NOT_NULL(a = dns_answer_new(0));
        ASSERT_OK(dns_answer_merge(a, a, &ret));
        ASSERT_PTR_EQ(ret, a);
        ret = dns_answer_unref(ret);

        ASSERT_NOT_NULL(b = dns_answer_new(0));
        ASSERT_OK_POSITIVE(dns_answer_add_soa(b, "example.com", 3600, 1));

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_PTR_EQ(ret, b);
        ret = dns_answer_unref(ret);

        ASSERT_OK(dns_answer_merge(b, a, &ret));
        ASSERT_PTR_EQ(ret, b);
        ret = dns_answer_unref(ret);

        ASSERT_NOT_NULL(rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_NOT_NULL(rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr_b->a.in_addr.s_addr = htobe32(0xc0a80180);
        ASSERT_OK_POSITIVE(dns_answer_add(b, rr_b, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_OK(dns_answer_merge(a, b, &ret));
        ASSERT_TRUE(ret != a);
        ASSERT_TRUE(ret != b);

        ASSERT_OK_POSITIVE(dns_answer_match_key(a, rr_a->key, /* ret_flags = */ NULL));
        ASSERT_OK_ZERO(dns_answer_match_key(a, rr_b->key, /* ret_flags = */ NULL));

        ASSERT_OK_ZERO(dns_answer_match_key(b, rr_a->key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(b, rr_b->key, /* ret_flags = */ NULL));

        ASSERT_OK_POSITIVE(dns_answer_match_key(ret, rr_a->key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(ret, rr_b->key, /* ret_flags = */ NULL));
}

/* ================================================================
 * dns_answer_extend()
 * ================================================================ */

TEST(dns_answer_extend) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = NULL, *b = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr_a = NULL, *rr_b = NULL;

        ASSERT_NOT_NULL(a = dns_answer_new(0));
        ASSERT_NOT_NULL(b = dns_answer_new(0));

        ASSERT_NOT_NULL(rr_a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr_a->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(a, rr_a, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_NOT_NULL(rr_b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr_b->a.in_addr.s_addr = htobe32(0xc0a80180);
        ASSERT_OK_POSITIVE(dns_answer_add(b, rr_b, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        ASSERT_OK(dns_answer_extend(&a, b));
        ASSERT_TRUE(a != b);

        ASSERT_OK_POSITIVE(dns_answer_match_key(a, rr_a->key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(a, rr_b->key, /* ret_flags = */ NULL));
}

/* ================================================================
 * dns_answer_remove_by_*()
 * ================================================================ */

static DnsAnswer* prepare_answer(void) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        char **hosts = STRV_MAKE("a.example.com", "b.example.com", "c.example.com");
        STRV_FOREACH(h, hosts) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, *h));
                rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
                ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        }

        return TAKE_PTR(answer);
}

TEST(dns_answer_remove_by_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();
        DnsResourceKey *key;

        /* ignore non-matching class */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "b.example.com"));
        ASSERT_OK_ZERO(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching type */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "b.example.com"));
        ASSERT_OK_ZERO(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* ignore non-matching name */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "z.example.com"));
        ASSERT_OK_ZERO(dns_answer_remove_by_key(&answer, key));
        ASSERT_EQ(dns_answer_size(answer), 3u);
        dns_resource_key_unref(key);

        /* remove matching key */
        char **hosts = STRV_MAKE("a.example.com", "b.example.com", "c.example.com");
        unsigned n = strv_length(hosts);
        STRV_FOREACH(h, hosts) {
                n--;

                ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, *h));
                ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
                ASSERT_OK_POSITIVE(dns_answer_remove_by_key(&answer, key));
                ASSERT_EQ(dns_answer_size(answer), n);

                ASSERT_OK_ZERO(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
                ASSERT_OK_ZERO(dns_answer_remove_by_key(&answer, key));
                ASSERT_EQ(dns_answer_size(answer), n);
                dns_resource_key_unref(key);
        }

        ASSERT_NULL(answer);
}

TEST(dns_answer_remove_by_rr) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = prepare_answer();

        char **hosts = STRV_MAKE("a.example.com", "b.example.com", "c.example.com");
        unsigned n = strv_length(hosts);
        STRV_FOREACH(h, hosts) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, *h));
                ASSERT_OK_POSITIVE(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));

                /* remove nothing if the payload does not match */
                ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, *h));
                rr->a.in_addr.s_addr = htobe32(0x01020304);
                ASSERT_OK_ZERO(dns_answer_remove_by_rr(&answer, rr));
                ASSERT_EQ(dns_answer_size(answer), n);

                /* remove matching payload */
                rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
                ASSERT_OK_POSITIVE(dns_answer_remove_by_rr(&answer, rr));
                ASSERT_EQ(dns_answer_size(answer), --n);

                ASSERT_OK_ZERO(dns_answer_match_key(answer, key, /* ret_flags = */ NULL));
        }

        ASSERT_NULL(answer);
}

TEST(dns_answer_remove_by_answer_keys) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *a = prepare_answer(), *b = prepare_answer();
        DnsResourceKey *key;

        ASSERT_OK(dns_answer_remove_by_answer_keys(&a, b));
        ASSERT_NULL(a);

        a = prepare_answer();

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_remove_by_key(&b, key));
        dns_resource_key_unref(key);

        ASSERT_EQ(dns_answer_size(a), 3u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        ASSERT_OK(dns_answer_remove_by_answer_keys(&a, b));

        ASSERT_EQ(dns_answer_size(a), 1u);
        ASSERT_EQ(dns_answer_size(b), 2u);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        ASSERT_OK_ZERO(dns_answer_match_key(a, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_match_key(a, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com"));
        ASSERT_OK_ZERO(dns_answer_match_key(a, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_copy_by_key()
 * ================================================================ */

TEST(dns_answer_copy_by_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = NULL, *target = NULL;
        DnsResourceRecord *rr;
        DnsResourceKey *key;
        DnsAnswerFlags flags;

        ASSERT_NOT_NULL(source = dns_answer_new(0));
        ASSERT_NOT_NULL(target = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */NULL));
        rr = dns_resource_record_unref(rr);

        /* non-matching class */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com"));
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching type */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching name */
        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* matching key */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 1u);
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));

        /* add one more record with the same key */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        /* check if the two records are copied */
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 2u);
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));

        /* try again with an empty target */
        target = dns_answer_unref(target);
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 2u);
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);

        /* add one more record */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        /* copy with flags */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        ASSERT_OK(dns_answer_copy_by_key(&target, source, key, DNS_ANSWER_SECTION_ANSWER, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(target), 3u);
        ASSERT_TRUE(dns_answer_match_key(target, key, &flags));
        ASSERT_EQ((int) flags, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ANSWER);
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_move_by_key()
 * ================================================================ */

TEST(dns_answer_move_by_key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *source = NULL, *target = NULL;
        DnsResourceRecord *rr;
        DnsResourceKey *key;

        ASSERT_NOT_NULL(source = dns_answer_new(0));
        ASSERT_NOT_NULL(target = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        /* non-matching class */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "a.example.com"));
        ASSERT_OK_ZERO(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching type */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "a.example.com"));
        ASSERT_OK_ZERO(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* non-matching name */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        ASSERT_OK_ZERO(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 0u);
        dns_resource_key_unref(key);

        /* matching key */
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_NULL(source);
        ASSERT_EQ(dns_answer_size(target), 1u);
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));

        /* move the record back to the source */
        source = TAKE_PTR(target);

        /* add one more record */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr->a.in_addr.s_addr = htobe32(0x7f000001);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        /* move only a.example.com */
        ASSERT_OK_POSITIVE(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 1u);
        ASSERT_OK_ZERO(dns_answer_match_key(source, key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));

        /* move the record back to the source */
        ASSERT_OK_POSITIVE(dns_answer_move_by_key(&source, &target, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 2u);
        ASSERT_EQ(dns_answer_size(target), 0u);

        /* add one more record */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a80180);
        ASSERT_OK_POSITIVE(dns_answer_add(source, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        /* move two records for a.example.com */
        ASSERT_OK_POSITIVE(dns_answer_move_by_key(&target, &source, key, /* or_flags = */ 0, /* rrsig = */ NULL));
        ASSERT_EQ(dns_answer_size(source), 1u);
        ASSERT_EQ(dns_answer_size(target), 2u);
        ASSERT_OK_ZERO(dns_answer_match_key(source, key, /* ret_flags = */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_match_key(target, key, /* ret_flags = */ NULL));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_answer_has_dname_for_cname()
 * ================================================================ */

TEST(dns_answer_has_dname_for_cname) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL, *rr = NULL;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        /* no dname */
        ASSERT_NOT_NULL(cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"));
        ASSERT_NOT_NULL(cname->cname.name = strdup("www.v2.example.com"));
        ASSERT_OK_ZERO(dns_answer_has_dname_for_cname(answer, cname));

        /* has matching dname */
        ASSERT_NOT_NULL(dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com"));
        ASSERT_NOT_NULL(dname->dname.name = strdup("v2.example.com"));
        ASSERT_OK_POSITIVE(dns_answer_add(answer, dname, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));

        /* no matching old suffix */
        ASSERT_OK(free_and_strdup(&dname->dname.name, "www.v2.examples.com"));
        ASSERT_OK_ZERO(dns_answer_has_dname_for_cname(answer, cname));
        ASSERT_OK(free_and_strdup(&dname->dname.name, "www.v2.example.com"));

        /* no matching new suffix */
        ASSERT_OK(free_and_strdup(&cname->cname.name, "www.v3.example.com"));
        ASSERT_OK_ZERO(dns_answer_has_dname_for_cname(answer, cname));

        /* Not a cname */
        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"));
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_ZERO(dns_answer_has_dname_for_cname(answer, rr));
}

/* ================================================================
 * dns_answer_dump()
 * ================================================================ */

TEST(dns_answer_dump) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr;
        _cleanup_(memstream_done) MemStream ms = {};
        _cleanup_free_ char *buf = NULL;
        FILE *f;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->ttl = 1200;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE | DNS_ANSWER_SECTION_ADDITIONAL, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr->ttl = 2400;
        rr->a.in_addr.s_addr = htobe32(0xc0a80180);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, 0, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com"));
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a80181);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 3,
                                          DNS_ANSWER_AUTHENTICATED | DNS_ANSWER_SHARED_OWNER | DNS_ANSWER_SECTION_AUTHORITY | DNS_ANSWER_CACHE_FLUSH,
                                          /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "d.example.com"));
        rr->ttl = 4800;
        rr->cname.name = strdup("www.example.com");
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 4, DNS_ANSWER_GOODBYE | DNS_ANSWER_SECTION_ANSWER, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_EQ(dns_answer_size(answer), 4u);

        ASSERT_NOT_NULL(f = memstream_init(&ms));
        dns_answer_dump(answer, f);
        ASSERT_OK(memstream_finalize(&ms, &buf, /* ret_size = */ NULL));
        ASSERT_STREQ(buf,
                     "\ta.example.com IN A 192.168.1.127\t; ttl=1200 ifindex=1 cacheable section-additional\n"
                     "\tb.example.com IN A 192.168.1.128\t; ttl=2400 ifindex=2\n"
                     "\tc.example.com IN A 192.168.1.129\t; ttl=3600 ifindex=3 authenticated shared-owner cache-flush section-authority\n"
                     "\td.example.com IN CNAME www.example.com\t; ttl=4800 ifindex=4 goodbye section-answer\n");
}

/* ================================================================
 * dns_answer_order_by_scope()
 * ================================================================ */

/* link-local addresses are a9fe0100 (169.254.1.0) to a9fefeff (169.254.254.255) */

TEST(dns_answer_order_by_scope) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceRecord *rr;
        _cleanup_(memstream_done) MemStream ms = {};
        _cleanup_free_ char *buf = NULL;
        FILE *f;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com"));
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fe0100);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 1, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com"));
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a80404);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "c.example.com"));
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fefeff);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig = */ NULL));
        dns_resource_record_unref(rr);

        dns_answer_order_by_scope(answer, /* prefer_link_local = */ true);

        ASSERT_NOT_NULL(f = memstream_init(&ms));
        dns_answer_dump(answer, f);
        ASSERT_OK(memstream_finalize(&ms, &buf, /* ret_size = */ NULL));
        ASSERT_STREQ(buf,
                     "\ta.example.com IN A 169.254.1.0\t; ttl=3600 ifindex=1 cacheable\n"
                     "\tc.example.com IN A 169.254.254.255\t; ttl=3600 ifindex=3 cacheable\n"
                     "\tb.example.com IN A 192.168.4.4\t; ttl=3600 ifindex=2 cacheable\n");
        buf = mfree(buf);
        memstream_done(&ms);

        dns_answer_order_by_scope(answer, /* prefer_link_local = */ false);

        ASSERT_NOT_NULL(f = memstream_init(&ms));
        dns_answer_dump(answer, f);
        ASSERT_OK(memstream_finalize(&ms, &buf, /* ret_size = */ NULL));
        ASSERT_STREQ(buf,
                     "\tb.example.com IN A 192.168.4.4\t; ttl=3600 ifindex=2 cacheable\n"
                     "\ta.example.com IN A 169.254.1.0\t; ttl=3600 ifindex=1 cacheable\n"
                     "\tc.example.com IN A 169.254.254.255\t; ttl=3600 ifindex=3 cacheable\n");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
