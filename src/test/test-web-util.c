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

TEST(url_add_port) {
        ASSERT_STREQ(http_url_add_port("http://192.0.2.0/journal/" , "19532"), "http://192.0.2.0:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("http://192.0.2.0/journal", "19532"), "http://192.0.2.0:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("http://[2001:db8::1]/journal", "19532"), "http://[2001:db8::1]:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("http://test.example.com/journal", "19532"), "http://test.example.com:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("http://ssyytteemmdd", "19532"), "http://ssyytteemmdd:19532/upload");

        ASSERT_STREQ(http_url_add_port("https://192.0.2.0:443/journal/", "19532"), "https://192.0.2.0:443/journal/upload");
        ASSERT_STREQ(http_url_add_port("https://192.0.2.0/journal/", "19532"), "https://192.0.2.0:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("https://[2001:db8::1]:443/journal", "19532"), "https://[2001:db8::1]:443/journal/upload");
        ASSERT_STREQ(http_url_add_port("https://[2001:db8::1]/journal", "19532"), "https://[2001:db8::1]:19532/journal/upload");
        ASSERT_STREQ(http_url_add_port("ssyytteemmdd", "19532"), "https://ssyytteemmdd:19532/upload");
}

DEFINE_TEST_MAIN(LOG_INFO);
