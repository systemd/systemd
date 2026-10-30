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

        test_provider_url_parse_one("", NULL, NULL);
        test_provider_url_parse_one("provider:", NULL, NULL);
        test_provider_url_parse_one("provider:[]/waldo", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]waldo", NULL, NULL);
        test_provider_url_parse_one("provider:[run/foobar]/waldo", NULL, NULL);     /* socket not absolute */
        test_provider_url_parse_one("provider:[/run//foobar]/waldo", NULL, NULL);   /* socket not normalized */
        test_provider_url_parse_one("provider:[/run/foobar]//waldo", NULL, NULL);   /* resource absolute */
        test_provider_url_parse_one("provider:[/run/foobar]/../waldo", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/a/./b", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/wal\ndo", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/waldo?x", NULL, NULL);
        test_provider_url_parse_one("provider:[/run/foobar]/waldo#x", NULL, NULL);
        test_provider_url_parse_one("https://example.com/waldo", NULL, NULL);
        test_provider_url_parse_one("provider:/run/foobar/waldo", NULL, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
