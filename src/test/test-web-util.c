/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

DEFINE_TEST_MAIN(LOG_INFO);
