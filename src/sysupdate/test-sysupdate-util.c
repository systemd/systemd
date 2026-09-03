/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysupdate-update-set-flags.h"
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

TEST(update_set_flags_to_string) {
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(0), "n/a");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_NEWEST), "current");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED), "current");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PENDING|UPDATE_NEWEST), "current+pending");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PARTIAL|UPDATE_PENDING|UPDATE_NEWEST), "current+partial");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_NEWEST), "candidate");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED), "candidate");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED), "installed");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PROTECTED), "protected");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE), "available");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_PROTECTED), "available");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_NEWEST), "current+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PROTECTED), "protected+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST), "current+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE), "installed+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST), "available+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST), "current+obsolete+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_PROTECTED), "protected+obsolete+incomplete");
}
