/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "glyph-util.h"
#include "kbd-util.h"
#include "locale-util.h"
#include "macro.h"
#include "strv.h"
#include "tests.h"

TEST(get_locales) {
        _cleanup_strv_free_ char **locales = NULL;
        int r;

        r = get_locales(&locales);
        ASSERT_OK(r);
        ASSERT_TRUE(locales);

        STRV_FOREACH(p, locales) {
                puts(*p);
                assert_se(locale_is_valid(*p));
        }
}

TEST(locale_is_valid) {
        ASSERT_TRUE(locale_is_valid("en_EN.utf8"));
        ASSERT_TRUE(locale_is_valid("fr_FR.utf8"));
        assert_se(locale_is_valid("fr_FR@euro"));
        ASSERT_TRUE(locale_is_valid("fi_FI"));
        ASSERT_TRUE(locale_is_valid("POSIX"));
        ASSERT_TRUE(locale_is_valid("C"));

        ASSERT_FALSE(locale_is_valid(""));
        assert_se(!locale_is_valid("/usr/bin/foo"));
        assert_se(!locale_is_valid("\x01gar\x02 bage\x03"));
}

TEST(locale_is_installed) {
        /* Always available */
        ASSERT_GT(locale_is_installed("POSIX"), 0);
        ASSERT_GT(locale_is_installed("C"), 0);

        /* Might, or might not be installed. */
        ASSERT_OK(locale_is_installed("en_EN.utf8"));
        ASSERT_OK(locale_is_installed("fr_FR.utf8"));
        assert_se(locale_is_installed("fr_FR@euro") >= 0);
        ASSERT_OK(locale_is_installed("fi_FI"));

        /* Definitely not valid */
        ASSERT_EQ(locale_is_installed(""), 0);
        assert_se(locale_is_installed("/usr/bin/foo") == 0);
        assert_se(locale_is_installed("\x01gar\x02 bage\x03") == 0);

        /* Definitely not installed */
        ASSERT_EQ(locale_is_installed("zz_ZZ"), 0);
}

TEST(keymaps) {
        _cleanup_strv_free_ char **kmaps = NULL;
        int r;

        ASSERT_FALSE(keymap_is_valid(""));
        assert_se(!keymap_is_valid("/usr/bin/foo"));
        assert_se(!keymap_is_valid("\x01gar\x02 bage\x03"));

        r = get_keymaps(&kmaps);
        if (r == -ENOENT)
                return; /* skip test if no keymaps are installed */

        ASSERT_OK(r);
        ASSERT_TRUE(kmaps);

        STRV_FOREACH(p, kmaps) {
                puts(*p);
                assert_se(keymap_is_valid(*p));
        }

        ASSERT_TRUE(keymap_is_valid("uk"));
        assert_se(keymap_is_valid("de-nodeadkeys"));
        assert_se(keymap_is_valid("ANSI-dvorak"));
        ASSERT_TRUE(keymap_is_valid("unicode"));
}

#define dump_glyph(x) log_info(STRINGIFY(x) ": %s", special_glyph(x))
TEST(dump_special_glyphs) {
        assert_cc(SPECIAL_GLYPH_GREEN_CIRCLE + 1 == _SPECIAL_GLYPH_MAX);

        log_info("is_locale_utf8: %s", yes_no(is_locale_utf8()));

        dump_glyph(SPECIAL_GLYPH_TREE_VERTICAL);
        dump_glyph(SPECIAL_GLYPH_TREE_BRANCH);
        dump_glyph(SPECIAL_GLYPH_TREE_RIGHT);
        dump_glyph(SPECIAL_GLYPH_TREE_SPACE);
        dump_glyph(SPECIAL_GLYPH_TREE_TOP);
        dump_glyph(SPECIAL_GLYPH_VERTICAL_DOTTED);
        dump_glyph(SPECIAL_GLYPH_HORIZONTAL_DOTTED);
        dump_glyph(SPECIAL_GLYPH_HORIZONTAL_FAT);
        dump_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET);
        dump_glyph(SPECIAL_GLYPH_BLACK_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_WHITE_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_MULTIPLICATION_SIGN);
        dump_glyph(SPECIAL_GLYPH_CIRCLE_ARROW);
        dump_glyph(SPECIAL_GLYPH_BULLET);
        dump_glyph(SPECIAL_GLYPH_MU);
        dump_glyph(SPECIAL_GLYPH_CHECK_MARK);
        dump_glyph(SPECIAL_GLYPH_CROSS_MARK);
        dump_glyph(SPECIAL_GLYPH_LIGHT_SHADE);
        dump_glyph(SPECIAL_GLYPH_DARK_SHADE);
        dump_glyph(SPECIAL_GLYPH_FULL_BLOCK);
        dump_glyph(SPECIAL_GLYPH_SIGMA);
        dump_glyph(SPECIAL_GLYPH_ARROW_UP);
        dump_glyph(SPECIAL_GLYPH_ARROW_DOWN);
        dump_glyph(SPECIAL_GLYPH_ARROW_LEFT);
        dump_glyph(SPECIAL_GLYPH_ARROW_RIGHT);
        dump_glyph(SPECIAL_GLYPH_ELLIPSIS);
        dump_glyph(SPECIAL_GLYPH_EXTERNAL_LINK);
        dump_glyph(SPECIAL_GLYPH_ECSTATIC_SMILEY);
        dump_glyph(SPECIAL_GLYPH_HAPPY_SMILEY);
        dump_glyph(SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY);
        dump_glyph(SPECIAL_GLYPH_NEUTRAL_SMILEY);
        dump_glyph(SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY);
        dump_glyph(SPECIAL_GLYPH_UNHAPPY_SMILEY);
        dump_glyph(SPECIAL_GLYPH_DEPRESSED_SMILEY);
        dump_glyph(SPECIAL_GLYPH_LOCK_AND_KEY);
        dump_glyph(SPECIAL_GLYPH_TOUCH);
        dump_glyph(SPECIAL_GLYPH_RECYCLING);
        dump_glyph(SPECIAL_GLYPH_DOWNLOAD);
        dump_glyph(SPECIAL_GLYPH_SPARKLES);
        dump_glyph(SPECIAL_GLYPH_LOW_BATTERY);
        dump_glyph(SPECIAL_GLYPH_WARNING_SIGN);
        dump_glyph(SPECIAL_GLYPH_COMPUTER_DISK);
        dump_glyph(SPECIAL_GLYPH_WORLD);
        dump_glyph(SPECIAL_GLYPH_RED_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_YELLOW_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_BLUE_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_GREEN_CIRCLE);
}

DEFINE_TEST_MAIN(LOG_INFO);
