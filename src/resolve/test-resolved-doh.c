/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-doh.h"
#include "tests.h"

TEST(content_type) {
        ASSERT_TRUE(dns_over_https_content_type_is_valid("application/dns-message"));
        ASSERT_TRUE(dns_over_https_content_type_is_valid("Application/DNS-Message"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid(NULL));
        ASSERT_FALSE(dns_over_https_content_type_is_valid(""));
        ASSERT_FALSE(dns_over_https_content_type_is_valid("application/dns-message; charset=binary"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid(" application/dns-message"));
        ASSERT_FALSE(dns_over_https_content_type_is_valid("application/dns-message "));
        ASSERT_FALSE(dns_over_https_content_type_is_valid("application/octet-stream"));
}

TEST(age) {
        uint64_t age = UINT64_MAX;

        ASSERT_TRUE(dns_over_https_age_parse("0", &age));
        ASSERT_EQ(age, 0u);
        ASSERT_TRUE(dns_over_https_age_parse("250", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse(" 250 \t", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse("250, 999", &age));
        ASSERT_EQ(age, 250u);
        ASSERT_TRUE(dns_over_https_age_parse("999999999999999999999999999999999999", &age));
        ASSERT_EQ(age, UINT64_MAX);

        ASSERT_FALSE(dns_over_https_age_parse(NULL, &age));
        ASSERT_FALSE(dns_over_https_age_parse("", &age));
        ASSERT_FALSE(dns_over_https_age_parse(" ", &age));
        ASSERT_FALSE(dns_over_https_age_parse("-1", &age));
        ASSERT_FALSE(dns_over_https_age_parse("1.0", &age));
        ASSERT_FALSE(dns_over_https_age_parse("invalid", &age));
}

TEST(uri_expand_for_method) {
        const uint8_t dns_message[] = { 0xfb, 0xff };
        _cleanup_free_ char *uri = NULL;

        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_POST, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/dns-query");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/dns-query?dns=-_8");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/custom?foo=bar{?dns}", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/custom?foo=bar&dns=-_8");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/custom?foo=bar{?dns}", DNS_OVER_HTTPS_METHOD_POST, dns_message, sizeof(dns_message), &uri));
        ASSERT_STREQ(uri, "https://resolver.example/custom?foo=bar");

        uri = mfree(uri);
        ASSERT_OK(dns_over_https_uri_expand_for_method("https://resolver.example/{?dns}/suffix", DNS_OVER_HTTPS_METHOD_GET, "foo", 3, &uri));
        ASSERT_STREQ(uri, "https://resolver.example/?dns=Zm9v/suffix");

        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query", DNS_OVER_HTTPS_METHOD_GET, dns_message, sizeof(dns_message), &uri), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", _DNS_OVER_HTTPS_METHOD_INVALID, dns_message, sizeof(dns_message), &uri), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_expand_for_method("https://resolver.example/dns-query{?dns}", DNS_OVER_HTTPS_METHOD_GET, NULL, sizeof(dns_message), &uri), EINVAL);
}

static void test_uri_parse_one(const char *uri_template, const char *expected_uri, const char *expected_auth_name, uint16_t expected_port) {
        _cleanup_free_ char *auth_name = NULL, *uri = NULL;
        uint16_t port = 0;

        ASSERT_OK(dns_over_https_uri_parse(uri_template, &uri, &auth_name, &port));
        ASSERT_STREQ(uri, expected_uri);
        ASSERT_STREQ(auth_name, expected_auth_name);
        ASSERT_EQ(port, expected_port);
}

TEST(uri_parse) {
        test_uri_parse_one("https://resolver.example", "https://resolver.example/", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/dns-query", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example:8443/custom{?dns}", "https://resolver.example:8443/custom", "resolver.example", 8443);
        test_uri_parse_one("https://resolver.example:/dns-query", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("HTTPS://resolver.example/dns-query{?dns}", "https://resolver.example/dns-query", "resolver.example", 443);
        test_uri_parse_one("https://resolver.example/custom?foo=bar{?dns}", "https://resolver.example/custom?foo=bar", "resolver.example", 443);
        test_uri_parse_one("https://192.0.2.1/dns-query", "https://192.0.2.1/dns-query", "192.0.2.1", 443);
        test_uri_parse_one("https://[2001:db8::1]/dns-query", "https://[2001:db8::1]/dns-query", "2001:db8::1", 443);
        test_uri_parse_one("https://[fe80::1%25eth0]/dns-query", "https://[fe80::1%25eth0]/dns-query", "fe80::1", 443);
}

TEST(uri_parse_invalid) {
        ASSERT_ERROR(dns_over_https_uri_parse("http://resolver.example/dns-query", NULL, NULL, NULL), EPROTONOSUPPORT);
        ASSERT_ERROR(dns_over_https_uri_parse("https:///dns-query", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://user@resolver.example/dns-query", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query#fragment", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query{dns}", NULL, NULL, NULL), EOPNOTSUPP);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query{?dns}{?dns}", NULL, NULL, NULL), EOPNOTSUPP);
        ASSERT_ERROR(dns_over_https_uri_parse("https://resolver.example/dns-query}{?dns}", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("https://[2001:db8::invalid]/dns-query", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("resolver.example/dns-query", NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(dns_over_https_uri_parse("", NULL, NULL, NULL), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
