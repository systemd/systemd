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

DEFINE_TEST_MAIN(LOG_INFO);
