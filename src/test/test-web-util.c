/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "web-util.h"

TEST(is_valid_documentation_url) {
        ASSERT_TRUE(documentation_url_is_valid("https://www.freedesktop.org/wiki/Software/systemd"));
        ASSERT_TRUE(documentation_url_is_valid("https://www.kernel.org/doc/Documentation/binfmt_misc.txt"));  /* dead */
        ASSERT_TRUE(documentation_url_is_valid("https://www.kernel.org/doc/Documentation/admin-guide/binfmt-misc.rst"));
        ASSERT_TRUE(documentation_url_is_valid("https://docs.kernel.org/admin-guide/binfmt-misc.html"));
        ASSERT_TRUE(documentation_url_is_valid("file:/foo/foo"));
        ASSERT_TRUE(documentation_url_is_valid("man:systemd.special(7)"));
        ASSERT_TRUE(documentation_url_is_valid("info:bar"));

        ASSERT_FALSE(documentation_url_is_valid("foo:"));
        ASSERT_FALSE(documentation_url_is_valid("info:"));
        ASSERT_FALSE(documentation_url_is_valid(""));
}

static void test_provider_url_parse_one(const char *url, const char *socket, const char *resource) {
        _cleanup_free_ char *s = NULL, *r = NULL;

        if (socket) {
                ASSERT_OK(provider_url_parse(url, &s, &r));
                ASSERT_STREQ(s, socket);
                ASSERT_STREQ(r, resource);
                ASSERT_TRUE(provider_url_is_valid(url));
        } else {
                ASSERT_ERROR(provider_url_parse(url, &s, &r), EINVAL);
                ASSERT_FALSE(provider_url_is_valid(url));
        }
}

TEST(provider_url_parse) {
        test_provider_url_parse_one("provider:[/run/foobar]/waldo", "/run/foobar", "waldo");
        test_provider_url_parse_one("provider:[/run/systemd/sysupdate/provider/io.foo]/pool/x-v1.raw", "/run/systemd/sysupdate/provider/io.foo", "pool/x-v1.raw");
        test_provider_url_parse_one("provider:[/run/foobar]/a/b/c", "/run/foobar", "a/b/c");

        test_provider_url_parse_one("", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[]/waldo", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]waldo", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[run/foobar]/waldo", /* socket= */ NULL, /* resource= */ NULL);     /* socket not absolute */
        test_provider_url_parse_one("provider:[/run//foobar]/waldo", /* socket= */ NULL, /* resource= */ NULL);   /* socket not normalized */
        test_provider_url_parse_one("provider:[/run/foobar]//waldo", /* socket= */ NULL, /* resource= */ NULL);   /* resource absolute */
        test_provider_url_parse_one("provider:[/run/foobar]/../waldo", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/a/./b", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/wal\ndo", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/waldo?x", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/waldo#x", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("https://example.com/waldo", /* socket= */ NULL, /* resource= */ NULL);
        test_provider_url_parse_one("provider:/run/foobar/waldo", /* socket= */ NULL, /* resource= */ NULL);
}

TEST(parse_content_range) {
        uint64_t start, end, total;

        ASSERT_OK(parse_content_range("bytes 0-9/10", &start, &end, &total));
        ASSERT_EQ(start, 0U);
        ASSERT_EQ(end, 9U);
        ASSERT_EQ(total, 10U);

        ASSERT_OK(parse_content_range("bytes 1000-5999/262164", &start, &end, &total));
        ASSERT_EQ(start, 1000U);
        ASSERT_EQ(end, 5999U);
        ASSERT_EQ(total, 262164U);

        /* Single byte ranges, case insensitive unit, unknown total */
        ASSERT_OK(parse_content_range("Bytes 7-7/*", &start, &end, &total));
        ASSERT_EQ(start, 7U);
        ASSERT_EQ(end, 7U);
        ASSERT_EQ(total, UINT64_MAX);

        ASSERT_OK(parse_content_range("bytes 0-18446744073709551613/18446744073709551614", &start, &end, &total));
        ASSERT_EQ(start, 0U);
        ASSERT_EQ(end, UINT64_MAX - 2);
        ASSERT_EQ(total, UINT64_MAX - 1);

        /* Leading zeros are permitted, and the numbers are always decimal, never octal */
        ASSERT_OK(parse_content_range("bytes 0100-0177/01000", &start, &end, &total));
        ASSERT_EQ(start, 100U);
        ASSERT_EQ(end, 177U);
        ASSERT_EQ(total, 1000U);

        ASSERT_OK(parse_content_range("bytes 08-09/010", &start, &end, &total));
        ASSERT_EQ(start, 8U);
        ASSERT_EQ(end, 9U);
        ASSERT_EQ(total, 10U);

        /* All return parameters are optional */
        ASSERT_OK(parse_content_range("bytes 0-9/10", /* ret_start= */ NULL, /* ret_end= */ NULL, /* ret_total= */ NULL));
        start = end = 0;
        ASSERT_OK(parse_content_range("bytes 3-4/*", &start, &end, /* ret_total= */ NULL));
        ASSERT_EQ(start, 3U);
        ASSERT_EQ(end, 4U);
        ASSERT_ERROR(parse_content_range("bytes 5-4/10", /* ret_start= */ NULL, /* ret_end= */ NULL, /* ret_total= */ NULL), EINVAL);

        /* End before start, or beyond the total */
        ASSERT_ERROR(parse_content_range("bytes 5-4/10", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-10/10", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-0/0", &start, &end, &total), EINVAL);

        /* The unsatisfied range form of 416 responses, other units, and malformed values */
        ASSERT_ERROR(parse_content_range("bytes */10", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("items 0-1/2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes ", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1/", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes -1/2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-/2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1/2x", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1/**", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes  0-1/2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes +0-1/2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1/-2", &start, &end, &total), EINVAL);
        ASSERT_ERROR(parse_content_range("bytes 0-1/2 ", &start, &end, &total), EINVAL);

        /* Overflow */
        ASSERT_ERROR(parse_content_range("bytes 0-18446744073709551616/*", &start, &end, &total), ERANGE);
        ASSERT_ERROR(parse_content_range("bytes 0-1/18446744073709551616", &start, &end, &total), ERANGE);
}

TEST(http_field_name_is_valid) {
        ASSERT_TRUE(http_field_name_is_valid("Authorization"));
        ASSERT_TRUE(http_field_name_is_valid("X-Foo-Bar"));
        ASSERT_TRUE(http_field_name_is_valid("x"));
        ASSERT_TRUE(http_field_name_is_valid("!#$%&'*+-.^_`|~09azAZ"));

        ASSERT_FALSE(http_field_name_is_valid(/* name= */ NULL));
        ASSERT_FALSE(http_field_name_is_valid(""));
        ASSERT_FALSE(http_field_name_is_valid("Foo Bar"));
        ASSERT_FALSE(http_field_name_is_valid("Foo:"));
        ASSERT_FALSE(http_field_name_is_valid("Foo\r\nBar"));
        ASSERT_FALSE(http_field_name_is_valid("Foo;"));
        ASSERT_FALSE(http_field_name_is_valid("(Foo)"));
        ASSERT_FALSE(http_field_name_is_valid("Fö"));
}

TEST(http_field_value_is_valid) {
        ASSERT_TRUE(http_field_value_is_valid(""));
        ASSERT_TRUE(http_field_value_is_valid("Bearer abc.def-ghi"));
        ASSERT_TRUE(http_field_value_is_valid("a,\tb, c"));
        ASSERT_TRUE(http_field_value_is_valid("Fööbar"));

        ASSERT_FALSE(http_field_value_is_valid(/* value= */ NULL));
        ASSERT_FALSE(http_field_value_is_valid("foo\r\nX-Injected: bar"));
        ASSERT_FALSE(http_field_value_is_valid("foo\nbar"));
        ASSERT_FALSE(http_field_value_is_valid("foo\rbar"));
        ASSERT_FALSE(http_field_value_is_valid("foo\x7f"));
        ASSERT_FALSE(http_field_value_is_valid("\x01"));
}

TEST(http_field_name_is_client_owned) {
        ASSERT_TRUE(http_field_name_is_client_owned("Host"));
        ASSERT_TRUE(http_field_name_is_client_owned("range"));
        ASSERT_TRUE(http_field_name_is_client_owned("ACCEPT-ENCODING"));
        ASSERT_TRUE(http_field_name_is_client_owned("Transfer-Encoding"));

        ASSERT_FALSE(http_field_name_is_client_owned(/* name= */ NULL));
        ASSERT_FALSE(http_field_name_is_client_owned("Authorization"));
        ASSERT_FALSE(http_field_name_is_client_owned("X-Foo"));
}

static void test_http_url_get_origin_one(const char *url, const char *expected) {
        _cleanup_free_ char *origin = NULL;

        log_debug("%s → %s", url, strna(expected));

        if (expected) {
                ASSERT_OK(http_url_get_origin(url, &origin));
                ASSERT_STREQ(origin, expected);
        } else
                ASSERT_ERROR(http_url_get_origin(url, &origin), EINVAL);
}

TEST(http_url_get_origin) {
        test_http_url_get_origin_one("http://example.com", "http://example.com:80");
        test_http_url_get_origin_one("http://example.com/", "http://example.com:80");
        test_http_url_get_origin_one("https://example.com/foo/bar?x=y#z", "https://example.com:443");
        test_http_url_get_origin_one("HTTPS://Example.COM/foo", "https://example.com:443");
        test_http_url_get_origin_one("https://example.com:443/foo", "https://example.com:443");
        test_http_url_get_origin_one("https://example.com:/foo", "https://example.com:443");
        test_http_url_get_origin_one("https://example.com:8443/foo", "https://example.com:8443");
        test_http_url_get_origin_one("http://example.com:0080", "http://example.com:80");
        test_http_url_get_origin_one("http://user:pass@example.com:81/", "http://example.com:81");
        test_http_url_get_origin_one("http://us@r@example.com/", "http://example.com:80");
        test_http_url_get_origin_one("http://example.com?foo@bar", "http://example.com:80");
        test_http_url_get_origin_one("http://example.com#foo@bar:1", "http://example.com:80");
        test_http_url_get_origin_one("http://127.0.0.1:8072/x", "http://127.0.0.1:8072");
        test_http_url_get_origin_one("http://[::1]/x", "http://[::1]:80");
        test_http_url_get_origin_one("http://[::1]:8080/x", "http://[::1]:8080");

        test_http_url_get_origin_one("file:///foo", /* expected= */ NULL);
        test_http_url_get_origin_one("ftp://example.com/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://", /* expected= */ NULL);
        test_http_url_get_origin_one("http:///foo", /* expected= */ NULL);
        test_http_url_get_origin_one("http://:80/foo", /* expected= */ NULL);
        test_http_url_get_origin_one("http://user@/foo", /* expected= */ NULL);
        test_http_url_get_origin_one("http://example.com:0/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://example.com:65536/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://example.com:+80/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://example.com:x/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://[::1/", /* expected= */ NULL);
        test_http_url_get_origin_one("http://[::1]x/", /* expected= */ NULL);
}

static void test_http_headers_parse_one(const char *text, int expected_error, char **expected) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_NOT_NULL(f = fmemopen_unlocked((char*) text, strlen(text), "r"));

        if (expected_error != 0) {
                ASSERT_ERROR(http_headers_parse(f, &l), expected_error);
                return;
        }

        ASSERT_OK(http_headers_parse(f, &l));
        ASSERT_TRUE(strv_equal(l, expected));
}

TEST(http_headers_parse) {
        test_http_headers_parse_one("", /* expected_error= */ 0, /* expected= */ NULL);
        test_http_headers_parse_one("\n\n", /* expected_error= */ 0, /* expected= */ NULL);
        test_http_headers_parse_one("Authorization: Bearer foo\n", /* expected_error= */ 0,
                                    STRV_MAKE("Authorization", "Bearer foo"));
        test_http_headers_parse_one("Authorization: Bearer foo", /* expected_error= */ 0,
                                    STRV_MAKE("Authorization", "Bearer foo"));
        test_http_headers_parse_one("A: b\r\nC:d\r\n\r\nE: \t f g \t\nX-Empty:\n", /* expected_error= */ 0,
                                    STRV_MAKE("A", "b", "C", "d", "E", "f g", "X-Empty", ""));
        test_http_headers_parse_one("X-Colon: a:b: c\n", /* expected_error= */ 0, STRV_MAKE("X-Colon", "a:b: c"));

        test_http_headers_parse_one("Foo\n", EINVAL, /* expected= */ NULL);
        test_http_headers_parse_one(": foo\n", EINVAL, /* expected= */ NULL);
        test_http_headers_parse_one("Foo : bar\n", EINVAL, /* expected= */ NULL);
        test_http_headers_parse_one(" Foo: bar\n", EINVAL, /* expected= */ NULL);
        test_http_headers_parse_one("Foo: b\x01r\n", EINVAL, /* expected= */ NULL);
        test_http_headers_parse_one("Foo: a\nfoo: b\n", ENOTUNIQ, /* expected= */ NULL);

        _cleanup_free_ char *many = NULL;
        for (unsigned i = 0; i <= HTTP_HEADERS_MAX; i++)
                ASSERT_OK(strextendf(&many, "X-%u: %u\n", i, i));
        test_http_headers_parse_one(many, E2BIG, /* expected= */ NULL);
}

TEST(http_headers_format) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(http_headers_format(/* headers= */ NULL, &s));
        ASSERT_STREQ(s, "");
        s = mfree(s);

        ASSERT_OK(http_headers_format(STRV_MAKE("Authorization", "Bearer foo", "X-Empty", ""), &s));
        ASSERT_STREQ(s, "Authorization: Bearer foo\nX-Empty: \n");

        /* Round trip */
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **l = NULL;
        ASSERT_NOT_NULL(f = fmemopen_unlocked(s, strlen(s), "r"));
        ASSERT_OK(http_headers_parse(f, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("Authorization", "Bearer foo", "X-Empty", "")));

        ASSERT_ERROR(http_headers_format(STRV_MAKE("X Foo", "bar"), &s), EINVAL);
        ASSERT_ERROR(http_headers_format(STRV_MAKE("X-Foo", "a\r\nX-Injected: b"), &s), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
