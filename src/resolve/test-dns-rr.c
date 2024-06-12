/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * DNS_RESOURCE_RECORD_RDATA()
 * ================================================================ */

TEST(dns_resource_record_rdata) {
        DnsResourceRecord rr = (DnsResourceRecord) {
                .wire_format = (void *)"abcdefghi",
                .wire_format_size = 9,
                .wire_format_rdata_offset = 3
        };

        const void *ptr = DNS_RESOURCE_RECORD_RDATA(&rr);
        ASSERT_STREQ(ptr, "defghi");

        size_t size = DNS_RESOURCE_RECORD_RDATA_SIZE(&rr);
        ASSERT_EQ(size, 6u);

        rr.wire_format = NULL;

        ptr = DNS_RESOURCE_RECORD_RDATA(&rr);
        ASSERT_NULL(ptr);

        size = DNS_RESOURCE_RECORD_RDATA_SIZE(&rr);
        ASSERT_EQ(size, 0u);
}

/* ================================================================
 * dns_resource_key_new()
 * ================================================================ */

TEST(dns_resource_key_new) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_EQ(key->class, DNS_CLASS_IN);
        ASSERT_EQ(key->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(key), "www.example.com");
}

/* ================================================================
 * dns_resource_key_new_redirect()
 * ================================================================ */

TEST(dns_resource_key_new_redirect_cname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        cname->cname.name = strdup("example.com");

        redirected = dns_resource_key_new_redirect(key, cname);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "example.com");
}

TEST(dns_resource_key_new_redirect_cname_no_match) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com");
        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        cname->cname.name = strdup("example.com");

        redirected = dns_resource_key_new_redirect(key, cname);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "example.com");
}

TEST(dns_resource_key_new_redirect_dname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        dname->dname.name = strdup("v2.example.com");

        redirected = dns_resource_key_new_redirect(key, dname);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "www.v2.example.com");
}

TEST(dns_resource_key_new_redirect_dname_no_match) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.examples.com");
        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        dname->dname.name = strdup("v2.example.com");

        redirected = dns_resource_key_new_redirect(key, dname);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "www.examples.com");
}

/* ================================================================
 * dns_resource_key_new_append_suffix()
 * ================================================================ */

TEST(dns_resource_key_new_append_suffix_root) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *source = NULL, *target = NULL;

        source = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)""));
        ASSERT_TRUE(target == source);

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)"."));
        ASSERT_TRUE(target == source);
}

TEST(dns_resource_key_new_append_suffix_not_root) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *source = NULL, *target = NULL;

        source = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)"com"));
        ASSERT_FALSE(target == source);
        ASSERT_STREQ(dns_resource_key_name(target), "www.example.com");
}

/* ================================================================
 * dns_resource_key_is_*()
 * ================================================================ */

TEST(dns_resource_key_is_address) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_TRUE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A6, "www.example.com");
        ASSERT_FALSE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_FALSE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);
}

TEST(dns_resource_key_is_dnssd_ptr) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_tcp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._tcp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_udp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "bar._udp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_tcp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_abc.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo_tcp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);
}

TEST(dns_resource_key_is_dnssd_two_label_ptr) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_tcp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._tcp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_udp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "bar._udp.local");
        ASSERT_TRUE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "foo._tcp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._abc.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo_tcp.local");
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * dns_resource_key_equal()
 * ================================================================ */

TEST(dns_resource_key_equal_same_pointer) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_resource_key_equal(a, a));
}

TEST(dns_resource_key_equal_equal_name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_resource_key_equal(a, b));
}

TEST(dns_resource_key_equal_case_insensitive_name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        ASSERT_TRUE(dns_resource_key_equal(a, b));
}

TEST(dns_resource_key_equal_trailing_dot) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com.");
        ASSERT_TRUE(dns_resource_key_equal(a, b));
}

TEST(dns_resource_key_equal_different_names) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        ASSERT_FALSE(dns_resource_key_equal(a, b));
}

TEST(dns_resource_key_equal_different_classes) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_FALSE(dns_resource_key_equal(a, b));
}

TEST(dns_resource_key_equal_different_types) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_FALSE(dns_resource_key_equal(a, b));
}

/* ================================================================
 * dns_resource_key_match_rr()
 * ================================================================ */

TEST(dns_resource_key_match_rr_simple) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_any_class) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_any_type) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_different_type) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_different_name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.other.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_case_insensitive_name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_escape_error) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_ERROR(dns_resource_key_match_rr(key, rr, NULL), EINVAL);
}

TEST(dns_resource_key_match_rr_search_domain) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_rr(key, rr, "com"));
}

TEST(dns_resource_key_match_rr_no_search_domain) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_rr(key, rr, NULL));
}

TEST(dns_resource_key_match_rr_different_search_domain) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_rr(key, rr, "org"));
}

/* ================================================================
 * dns_resource_key_match_cname_or_dname()
 * ================================================================ */

TEST(dns_resource_key_match_cname_or_dname_simple) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_any_class) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_bad_type) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_NSEC, "www.example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_case_insensitive_cname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_prefix_cname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_suffix_cname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_search_domain_cname_pass) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, "com"));
}

TEST(dns_resource_key_match_cname_or_dname_search_domain_cname_fail) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, "org"));
}

TEST(dns_resource_key_match_cname_or_dname_case_insensitive_dname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNAME, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_prefix_dname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_suffix_dname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNAME, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, NULL));
}

TEST(dns_resource_key_match_cname_or_dname_search_domain_dname_pass) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");

        ASSERT_TRUE(dns_resource_key_match_cname_or_dname(key, cname, "com"));
}

TEST(dns_resource_key_match_cname_or_dname_search_domain_dname_fail) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        cname = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");

        ASSERT_FALSE(dns_resource_key_match_cname_or_dname(key, cname, "org"));
}

/* ================================================================
 * dns_resource_key_match_soa()
 * ================================================================ */

TEST(dns_resource_key_match_soa_simple) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *soa = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        soa = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");

        ASSERT_TRUE(dns_resource_key_match_soa(key, soa));
}

TEST(dns_resource_key_no_match_soa_any_class) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *soa = NULL;

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        soa = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_soa(key, soa));
}

TEST(dns_resource_key_no_match_soa_bad_type) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *soa = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        soa = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_soa(key, soa));
}

TEST(dns_resource_key_match_soa_child_domain) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *soa = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        soa = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");

        ASSERT_TRUE(dns_resource_key_match_soa(key, soa));
}

TEST(dns_resource_key_no_match_soa_parent_domain) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *soa = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        soa = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");

        ASSERT_FALSE(dns_resource_key_match_soa(key, soa));
}

/* ================================================================
 * dns_resource_key_to_string()
 * ================================================================ */

TEST(dns_resource_key_to_string) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        char str[256];

        char *ans = dns_resource_key_to_string(key, str, 256);
        ASSERT_TRUE(ans == str);
        ASSERT_STREQ(ans, "www.example.com IN CNAME");
}

/* ================================================================
 * dns_resource_key_reduce()
 * ================================================================ */

TEST(dns_resource_key_reduce_same_pointer) {
        DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = a;

        ASSERT_TRUE(dns_resource_key_reduce(&a, &b));
        ASSERT_TRUE(a == b);

        dns_resource_key_unref(a);
}

TEST(dns_resource_key_reduce_same_values) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(a != b);

        ASSERT_TRUE(dns_resource_key_reduce(&a, &b));
        ASSERT_TRUE(a == b);
}

TEST(dns_resource_key_reduce_different_values) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        ASSERT_TRUE(a != b);

        ASSERT_FALSE(dns_resource_key_reduce(&a, &b));
        ASSERT_TRUE(a != b);
}

TEST(dns_resource_key_reduce_refcount) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *a = NULL, *b = NULL, *c = NULL;

        a = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        c = b;

        ASSERT_TRUE(a != b);

        a->n_ref = 3;
        b->n_ref = 2;

        ASSERT_TRUE(dns_resource_key_reduce(&a, &b));
        ASSERT_TRUE(a == b);

        ASSERT_EQ(a->n_ref, 4u);
        ASSERT_EQ(c->n_ref, 1u);
}

/* ================================================================
 * dns_resource_record_new_address()
 * ================================================================ */

TEST(dns_resource_record_new_address_ipv4) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        union in_addr_union addr = { .in.s_addr = htobe32(0xc0a8017f) };

        ASSERT_OK(dns_resource_record_new_address(&rr, AF_INET, &addr, "www.example.com"));

        ASSERT_EQ(rr->key->class, DNS_CLASS_IN);
        ASSERT_EQ(rr->key->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(rr->key), "www.example.com");
        ASSERT_EQ(rr->a.in_addr.s_addr, addr.in.s_addr);
}

TEST(dns_resource_record_new_address_ipv6) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        union in_addr_union addr = {
                .in6.s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 }
        };

        ASSERT_OK(dns_resource_record_new_address(&rr, AF_INET6, &addr, "www.example.com"));

        ASSERT_EQ(rr->key->class, DNS_CLASS_IN);
        ASSERT_EQ(rr->key->type, DNS_TYPE_AAAA);
        ASSERT_STREQ(dns_resource_key_name(rr->key), "www.example.com");
        ASSERT_EQ(memcmp(&rr->aaaa.in6_addr, &addr.in6, sizeof(struct in6_addr)), 0);
}

/* ================================================================
 * dns_resource_record_new_reverse()
 * ================================================================ */

TEST(dns_resource_record_new_reverse) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        union in_addr_union addr = { .in.s_addr = htobe32(0xc0a8017f) };

        ASSERT_OK(dns_resource_record_new_reverse(&rr, AF_INET, &addr, "www.example.com"));

        ASSERT_EQ(rr->key->class, DNS_CLASS_IN);
        ASSERT_EQ(rr->key->type, DNS_TYPE_PTR);
        ASSERT_STREQ(dns_resource_key_name(rr->key), "127.1.168.192.in-addr.arpa");
        ASSERT_STREQ(rr->ptr.name, "www.example.com");
}

/* ================================================================
 * dns_resource_record_equal() : general cases
 * ================================================================ */

TEST(dns_resource_record_equal_same_pointer) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_resource_record_equal(a, a));
}

TEST(dns_resource_record_equal_equal_name) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_case_insensitive_name) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_trailing_dot) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com.");
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_different_names) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_different_classes) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_different_types) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        b = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : A, AAAA
 * ================================================================ */

TEST(dns_resource_record_equal_a_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        a->a.in_addr.s_addr = htobe32(0xc0a8017f);

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_a_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        a->a.in_addr.s_addr = htobe32(0xc0a8017f);

        b = dns_resource_record_copy(a);
        b->a.in_addr.s_addr = htobe32(0xc0a80180);
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_aaaa_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        a->aaaa.in6_addr = (struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 } };

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_aaaa_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        a->aaaa.in6_addr = (struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 } };

        b = dns_resource_record_copy(a);
        b->aaaa.in6_addr = (struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04 } };
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : NS
 * ================================================================ */

TEST(dns_resource_record_equal_ns_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "www.example.com");
        a->ns.name = strdup("ns1.example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_ns_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "www.example.com");
        a->ns.name = strdup("ns1.example.com");

        b = dns_resource_record_copy(a);
        b->ns.name = strdup("ns2.example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : CNAME
 * ================================================================ */

TEST(dns_resource_record_equal_cname_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        a->cname.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_cname_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        a->cname.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        b->cname.name = strdup("example.orb");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : DNAME
 * ================================================================ */

TEST(dns_resource_record_equal_dname) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "www.example.com");
        a->dname.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_dname_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "www.example.com");
        a->dname.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        b->dname.name = strdup("example.orb");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : SOA
 * ================================================================ */

TEST(dns_resource_record_equal_soa_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_mname) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.mname = strdup("ns.example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_rname) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.rname = strdup("admin.example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_serial) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.serial = 1111111112;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_refresh) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.refresh = 86401;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_retry) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.retry = 7201;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_expire) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.expire = 4000001;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_soa_bad_minimum) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a->soa.mname = strdup("ns.example.com");
        a->soa.rname = strdup("admin.example.com");
        a->soa.serial = 1111111111;
        a->soa.refresh = 86400;
        a->soa.retry = 7200;
        a->soa.expire = 4000000;
        a->soa.minimum = 3600;

        b = dns_resource_record_copy(a);
        b->soa.minimum = 3601;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : PTR
 * ================================================================ */

TEST(dns_resource_record_equal_ptr_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "127.1.168.192.in-addr-arpa");
        a->ptr.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_ptr_fail) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "127.1.168.192.in-addr-arpa");
        a->ptr.name = strdup("example.com");

        b = dns_resource_record_copy(a);
        b->ptr.name = strdup("example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : HINFO
 * ================================================================ */

TEST(dns_resource_record_equal_hinfo_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        a->hinfo.cpu = strdup("intel x64");
        a->hinfo.os = strdup("linux");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_hinfo_case_insensitive) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        a->hinfo.cpu = strdup("intel x64");
        a->hinfo.os = strdup("linux");

        b = dns_resource_record_copy(a);
        b->hinfo.cpu = strdup("INTEL x64");
        b->hinfo.os = strdup("LINUX");
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_hinfo_bad_cpu) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        a->hinfo.cpu = strdup("intel x64");
        a->hinfo.os = strdup("linux");

        b = dns_resource_record_copy(a);
        b->hinfo.cpu = strdup("arm64");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_hinfo_bad_os) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        a->hinfo.cpu = strdup("intel x64");
        a->hinfo.os = strdup("linux");

        b = dns_resource_record_copy(a);
        b->hinfo.os = strdup("windows");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : MX
 * ================================================================ */

TEST(dns_resource_record_equal_mx_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_MX, "www.example.com");
        a->mx.priority = 10;
        a->mx.exchange = strdup("mail.example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_mx_bad_priority) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_MX, "www.example.com");
        a->mx.priority = 10;
        a->mx.exchange = strdup("mail.example.com");

        b = dns_resource_record_copy(a);
        b->mx.priority = 9;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_mx_bad_exchange) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_MX, "www.example.com");
        a->mx.priority = 10;
        a->mx.exchange = strdup("mail.example.com");

        b = dns_resource_record_copy(a);
        b->mx.exchange = strdup("mail.example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : TXT
 * ================================================================ */

TEST(dns_resource_record_equal_txt_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        const char *data = "the quick brown fox and so on";
        size_t len = strlen(data);

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        a->txt.items = calloc(1, offsetof(DnsTxtItem, data) + len + 1);
        a->txt.items->length = len;
        memcpy(a->txt.items->data, data, len);

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_txt_missing) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        const char *data = "the quick brown fox and so on";
        size_t len = strlen(data);

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        a->txt.items = calloc(1, offsetof(DnsTxtItem, data) + len + 1);
        a->txt.items->length = len;
        memcpy(a->txt.items->data, data, len);

        b = dns_resource_record_copy(a);
        dns_txt_item_new_empty(&b->txt.items);
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_txt_different_text) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        const char *data = "the quick brown fox and so on";
        size_t len = strlen(data);

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        a->txt.items = calloc(1, offsetof(DnsTxtItem, data) + len + 1);
        a->txt.items->length = len;
        memcpy(a->txt.items->data, data, len);

        const char *other_data = "jumped over, etc";

        b = dns_resource_record_copy(a);
        b->txt.items->length = strlen(other_data);
        memcpy(b->txt.items->data, other_data, strlen(other_data));
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : SRV
 * ================================================================ */

TEST(dns_resource_record_equal_srv_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        a->srv.name = strdup("mail.example.com");
        a->srv.priority = 10;
        a->srv.weight = 5;
        a->srv.port = 587;

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_srv_bad_name) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        a->srv.name = strdup("mail.example.com");
        a->srv.priority = 10;
        a->srv.weight = 5;
        a->srv.port = 587;

        b = dns_resource_record_copy(a);
        b->srv.name = strdup("example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_srv_bad_priority) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        a->srv.name = strdup("mail.example.com");
        a->srv.priority = 10;
        a->srv.weight = 5;
        a->srv.port = 587;

        b = dns_resource_record_copy(a);
        b->srv.priority = 9;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_srv_bad_weight) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        a->srv.name = strdup("mail.example.com");
        a->srv.priority = 10;
        a->srv.weight = 5;
        a->srv.port = 587;

        b = dns_resource_record_copy(a);
        b->srv.weight = 6;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_srv_bad_port) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        a->srv.name = strdup("mail.example.com");
        a->srv.priority = 10;
        a->srv.weight = 5;
        a->srv.port = 587;

        b = dns_resource_record_copy(a);
        b->srv.port = 588;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : NAPTR
 * ================================================================ */

TEST(dns_resource_record_equal_naptr_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_order) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.order = 103;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_preference) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.preference = 9;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.flags = strdup("S");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_services) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.services = strdup("E2U-sip");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_regexp) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.regexp = strdup("a*");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_naptr_bad_replacement) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
        a->naptr.order = 102;
        a->naptr.preference = 10;
        a->naptr.flags = strdup("U");
        a->naptr.services = strdup("E2U+sip");
        a->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        a->naptr.replacement = strdup("_sip._udp.example.com");

        b = dns_resource_record_copy(a);
        b->naptr.replacement = strdup("_sip._udp.example.org");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : RRSIG
 * ================================================================ */

TEST(dns_resource_record_equal_rrsig_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_type_covered) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.type_covered = DNS_TYPE_AAAA;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_algorithm) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.algorithm = DNSSEC_ALGORITHM_DSA;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_labels) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.labels = 2;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_original_ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.original_ttl = 3601;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_expiration) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.expiration = a->rrsig.expiration + 1;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_inception) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.inception = a->rrsig.inception - 1;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_key_tag) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.key_tag = 0x4321;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_signer) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.signer = strdup("www.example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_rrsig_bad_signature) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        a->rrsig.type_covered = DNS_TYPE_A;
        a->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        a->rrsig.labels = 3;
        a->rrsig.original_ttl = 3600;
        a->rrsig.expiration = 1720361303;
        a->rrsig.inception = 1717769303;
        a->rrsig.key_tag = 0x1234;
        a->rrsig.signer = strdup("example.com");

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };
        a->rrsig.signature_size = sizeof(signature);
        a->rrsig.signature = memdup(signature, a->rrsig.signature_size);

        b = dns_resource_record_copy(a);
        b->rrsig.signature_size -= 1;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

/* ================================================================
 * dns_resource_record_equal() : SVCB
 * ================================================================ */

TEST(dns_resource_record_equal_svcb_copy) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;
        DnsSvcParam *param = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, a->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 2);
        param->key = 99;
        param->length = 0;
        LIST_APPEND(params, a->svcb.params, param);

        b = dns_resource_record_copy(a);
        ASSERT_TRUE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_svcb_bad_priority) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        b = dns_resource_record_copy(a);
        b->svcb.priority = 8;
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_svcb_bad_target_name) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        b = dns_resource_record_copy(a);
        b->svcb.target_name = strdup("other.example.com");
        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_svcb_param_missing) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;
        DnsSvcParam *param = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        b = dns_resource_record_copy(a);

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, a->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 2);
        param->key = 99;
        param->length = 0;
        LIST_APPEND(params, a->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, b->svcb.params, param);

        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_svcb_param_extra) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;
        DnsSvcParam *param = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        b = dns_resource_record_copy(a);

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, a->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, b->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 2);
        param->key = 99;
        param->length = 0;
        LIST_APPEND(params, b->svcb.params, param);

        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

TEST(dns_resource_record_equal_svcb_param_different) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *b = NULL;
        DnsSvcParam *param = NULL;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        a->svcb.priority = 9;
        a->svcb.target_name = strdup("sock.example.com");

        b = dns_resource_record_copy(a);

        param = calloc(1, offsetof(DnsSvcParam, value) + 10);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 10;
        memcpy(param->value, "\x09websocket", 10);
        LIST_APPEND(params, a->svcb.params, param);

        param = calloc(1, offsetof(DnsSvcParam, value) + 5);
        param->key = DNS_SVC_PARAM_KEY_ALPN;
        param->length = 5;
        memcpy(param->value, "\x04xmpp", 5);
        LIST_APPEND(params, b->svcb.params, param);

        ASSERT_FALSE(dns_resource_record_equal(a, b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
