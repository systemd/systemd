/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "glyph-util.h"
#include "kbd-util.h"
#include "locale-util.h"
#include "strv.h"
#include "tests.h"

TEST(get_locales) {
        _cleanup_strv_free_ char **locales = NULL;
        int r;

        r = get_locales(&locales);
        assert_se(r >= 0);
        assert_se(locales);

        STRV_FOREACH(p, locales) {
                puts(*p);
                assert_se(locale_is_valid(*p));
        }
}

TEST(locale_is_valid) {
        assert_se(locale_is_valid("en_EN.utf8"));
        assert_se(locale_is_valid("fr_FR.utf8"));
        assert_se(locale_is_valid("fr_FR@euro"));
        assert_se(locale_is_valid("fi_FI"));
        assert_se(locale_is_valid("POSIX"));
        assert_se(locale_is_valid("C"));

        assert_se(!locale_is_valid(""));
        assert_se(!locale_is_valid("/usr/bin/foo"));
        assert_se(!locale_is_valid("\x01gar\x02 bage\x03"));
}

TEST(locale_is_installed) {
        /* Always available */
        assert_se(locale_is_installed("POSIX") > 0);
        assert_se(locale_is_installed("C") > 0);

        /* Might, or might not be installed. */
        assert_se(locale_is_installed("en_EN.utf8") >= 0);
        assert_se(locale_is_installed("fr_FR.utf8") >= 0);
        assert_se(locale_is_installed("fr_FR@euro") >= 0);
        assert_se(locale_is_installed("fi_FI") >= 0);

        /* Definitely not valid */
        assert_se(locale_is_installed("") == 0);
        assert_se(locale_is_installed("/usr/bin/foo") == 0);
        assert_se(locale_is_installed("\x01gar\x02 bage\x03") == 0);

        /* Definitely not installed */
#ifdef __GLIBC__
        ASSERT_OK_ZERO(locale_is_installed("zz_ZZ"));
#else
        /* musl seems to return a non-null locale object even if it is not installed. */
        ASSERT_OK_POSITIVE(locale_is_installed("zz_ZZ"));
#endif
}

TEST(keymaps) {
        _cleanup_strv_free_ char **kmaps = NULL;
        int r;

        assert_se(!keymap_is_valid(""));
        assert_se(!keymap_is_valid("/usr/bin/foo"));
        assert_se(!keymap_is_valid("\x01gar\x02 bage\x03"));

        r = get_keymaps(&kmaps);
        if (r == -ENOENT)
                return; /* skip test if no keymaps are installed */

        assert_se(r >= 0);
        assert_se(kmaps);

        STRV_FOREACH(p, kmaps) {
                puts(*p);
                assert_se(keymap_is_valid(*p));
        }

        assert_se(keymap_is_valid("uk"));
        assert_se(keymap_is_valid("de-nodeadkeys"));
        assert_se(keymap_is_valid("ANSI-dvorak"));
        assert_se(keymap_is_valid("unicode"));
}

#define dump_glyph(x) log_info(STRINGIFY(x) ": %s", glyph(x))
TEST(dump_glyphs) {
        assert_cc(GLYPH_SHELL + 1 == _GLYPH_MAX);

        log_info("is_locale_utf8: %s", yes_no(is_locale_utf8()));

        dump_glyph(GLYPH_TREE_VERTICAL);
        dump_glyph(GLYPH_TREE_BRANCH);
        dump_glyph(GLYPH_TREE_RIGHT);
        dump_glyph(GLYPH_TREE_SPACE);
        dump_glyph(GLYPH_TREE_TOP);
        dump_glyph(GLYPH_VERTICAL_DOTTED);
        dump_glyph(GLYPH_HORIZONTAL_DOTTED);
        dump_glyph(GLYPH_HORIZONTAL_FAT);
        dump_glyph(GLYPH_TRIANGULAR_BULLET);
        dump_glyph(GLYPH_BLACK_CIRCLE);
        dump_glyph(GLYPH_WHITE_CIRCLE);
        dump_glyph(GLYPH_MULTIPLICATION_SIGN);
        dump_glyph(GLYPH_CIRCLE_ARROW);
        dump_glyph(GLYPH_BULLET);
        dump_glyph(GLYPH_MU);
        dump_glyph(GLYPH_CHECK_MARK);
        dump_glyph(GLYPH_CROSS_MARK);
        dump_glyph(GLYPH_LIGHT_SHADE);
        dump_glyph(GLYPH_DARK_SHADE);
        dump_glyph(GLYPH_FULL_BLOCK);
        dump_glyph(GLYPH_SIGMA);
        dump_glyph(GLYPH_ARROW_UP);
        dump_glyph(GLYPH_ARROW_DOWN);
        dump_glyph(GLYPH_ARROW_LEFT);
        dump_glyph(GLYPH_ARROW_RIGHT);
        dump_glyph(GLYPH_ELLIPSIS);
        dump_glyph(GLYPH_EXTERNAL_LINK);
        dump_glyph(GLYPH_ECSTATIC_SMILEY);
        dump_glyph(GLYPH_HAPPY_SMILEY);
        dump_glyph(GLYPH_SLIGHTLY_HAPPY_SMILEY);
        dump_glyph(GLYPH_NEUTRAL_SMILEY);
        dump_glyph(GLYPH_SLIGHTLY_UNHAPPY_SMILEY);
        dump_glyph(GLYPH_UNHAPPY_SMILEY);
        dump_glyph(GLYPH_DEPRESSED_SMILEY);
        dump_glyph(GLYPH_LOCK_AND_KEY);
        dump_glyph(GLYPH_TOUCH);
        dump_glyph(GLYPH_RECYCLING);
        dump_glyph(GLYPH_DOWNLOAD);
        dump_glyph(GLYPH_SPARKLES);
        dump_glyph(GLYPH_LOW_BATTERY);
        dump_glyph(GLYPH_WARNING_SIGN);
        dump_glyph(GLYPH_COMPUTER_DISK);
        dump_glyph(GLYPH_WORLD);
        dump_glyph(GLYPH_RED_CIRCLE);
        dump_glyph(GLYPH_YELLOW_CIRCLE);
        dump_glyph(GLYPH_BLUE_CIRCLE);
        dump_glyph(GLYPH_GREEN_CIRCLE);
        dump_glyph(GLYPH_SUPERHERO);
        dump_glyph(GLYPH_IDCARD);
        dump_glyph(GLYPH_HOME);
        dump_glyph(GLYPH_ROCKET);
        dump_glyph(GLYPH_BROOM);
        dump_glyph(GLYPH_KEYBOARD);
        dump_glyph(GLYPH_CLOCK);
        dump_glyph(GLYPH_LABEL);
        dump_glyph(GLYPH_SHELL);
}

DEFINE_TEST_MAIN(LOG_INFO);
