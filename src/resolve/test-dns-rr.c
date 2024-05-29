/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
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
        ASSERT_NOT_NULL(key);

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
        ASSERT_NOT_NULL(key);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("example.com");

        redirected = dns_resource_key_new_redirect(key, cname);
        ASSERT_NOT_NULL(redirected);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "example.com");
}

TEST(dns_resource_key_new_redirect_cname_no_match) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "mail.example.com");
        ASSERT_NOT_NULL(key);

        cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(cname);
        cname->cname.name = strdup("example.com");

        redirected = dns_resource_key_new_redirect(key, cname);
        ASSERT_NOT_NULL(redirected);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "example.com");
}

TEST(dns_resource_key_new_redirect_dname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.example.com");

        redirected = dns_resource_key_new_redirect(key, dname);
        ASSERT_NOT_NULL(redirected);

        ASSERT_EQ(redirected->class, DNS_CLASS_IN);
        ASSERT_EQ(redirected->type, DNS_TYPE_A);
        ASSERT_STREQ(dns_resource_key_name(redirected), "www.v2.example.com");
}

TEST(dns_resource_key_new_redirect_dname_no_match) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL, *redirected = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dname = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.examples.com");
        ASSERT_NOT_NULL(key);

        dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(dname);
        dname->dname.name = strdup("v2.example.com");

        redirected = dns_resource_key_new_redirect(key, dname);
        ASSERT_NOT_NULL(redirected);

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
        ASSERT_NOT_NULL(source);

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)""));
        ASSERT_NOT_NULL(target);
        ASSERT_TRUE(target == source);

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)"."));
        ASSERT_NOT_NULL(target);
        ASSERT_TRUE(target == source);

        dns_resource_key_unref(source);
}

TEST(dns_resource_key_new_append_suffix_not_root) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *source = NULL, *target = NULL;

        source = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        ASSERT_NOT_NULL(source);

        ASSERT_OK(dns_resource_key_new_append_suffix(&target, source, (char *)"com"));
        ASSERT_NOT_NULL(target);
        ASSERT_FALSE(target == source);
        ASSERT_STREQ(dns_resource_key_name(target), "www.example.com");
}

/* ================================================================
 * dns_resource_key_is_*()
 * ================================================================ */

TEST(dns_resource_key_is_address) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A6, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_address(key));
        dns_resource_key_unref(key);
}

TEST(dns_resource_key_is_dnssd_ptr) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_udp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "bar._udp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "_tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_abc.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo_tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_ptr(key));
        dns_resource_key_unref(key);
}

TEST(dns_resource_key_is_dnssd_two_label_ptr) {
        DnsResourceKey *key = NULL;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_udp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "bar._udp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "foo._tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._abc.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo_tcp.local");
        ASSERT_NOT_NULL(key);
        ASSERT_FALSE(dns_resource_key_is_dnssd_two_label_ptr(key));
        dns_resource_key_unref(key);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
