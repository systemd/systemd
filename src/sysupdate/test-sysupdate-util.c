/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "glyph-util.h"
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

TEST(update_set_flags_glyph) {
        ASSERT_STREQ(update_set_flags_to_glyph(UPDATE_INSTALLED|UPDATE_INCOMPLETE), " ");
        ASSERT_STREQ(update_set_flags_to_glyph(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PENDING), " ");
        ASSERT_STREQ(update_set_flags_to_glyph(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_NEWEST), glyph(GLYPH_BLACK_CIRCLE));
        ASSERT_STREQ(update_set_flags_to_glyph(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PROTECTED), glyph(GLYPH_WHITE_CIRCLE));
        ASSERT_STREQ(update_set_flags_to_glyph(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PARTIAL|UPDATE_PENDING), glyph(GLYPH_DOWNLOAD));
}

DEFINE_TEST_MAIN(LOG_INFO);
