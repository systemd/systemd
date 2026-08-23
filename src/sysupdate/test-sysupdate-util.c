/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysupdate-util.h"
#include "tests.h"

TEST(component_name_valid) {
        /* Valid component names: anything that turns "sysupdate.<name>.d" into a valid filename. */
        ASSERT_TRUE(component_name_valid("foo"));
        ASSERT_TRUE(component_name_valid("foo-bar"));
        ASSERT_TRUE(component_name_valid("foo.bar"));
        ASSERT_TRUE(component_name_valid("foo_bar_baz"));
        ASSERT_TRUE(component_name_valid("0815"));
        ASSERT_TRUE(component_name_valid("über"));            /* valid UTF-8 is fine */

        /* Invalid: empty, slashes, control characters, invalid UTF-8. */
        ASSERT_FALSE(component_name_valid(""));
        ASSERT_FALSE(component_name_valid("foo/bar"));
        ASSERT_FALSE(component_name_valid("/foo"));
        ASSERT_FALSE(component_name_valid("foo/"));
        ASSERT_FALSE(component_name_valid("foo\tbar"));
        ASSERT_FALSE(component_name_valid("foo\nbar"));
        ASSERT_FALSE(component_name_valid("foo\x7f"));
        ASSERT_FALSE(component_name_valid("\xff"));           /* not valid UTF-8 */
}

DEFINE_TEST_MAIN(LOG_INFO);
