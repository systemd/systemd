/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "kbd-util.h"
#include "locale-util.h"
#include "macro.h"
#include "strv.h"
#include "util.h"

static void test_get_locales(void) {
        _cleanup_strv_free_ char **locales = NULL;
        char **p;
        int r;

        r = get_locales(&locales);
        assert_se(r >= 0);
        assert_se(locales);

        STRV_FOREACH(p, locales) {
                puts(*p);
                assert_se(locale_is_valid(*p));
        }
}

static void test_locale_is_valid(void) {
        log_info("/* %s */", __func__);

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

static void test_locale_is_installed(void) {
        log_info("/* %s */", __func__);

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
        assert_se(locale_is_installed("zz_ZZ") == 0);
}

static void test_keymaps(void) {
        _cleanup_strv_free_ char **kmaps = NULL;
        char **p;
        int r;

        log_info("/* %s */", __func__);

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

#define dump_glyph(x) log_info(STRINGIFY(x) ": %s", special_glyph(x))
static void dump_special_glyphs(void) {
        assert_cc(SPECIAL_GLYPH_TOUCH + 1 == _SPECIAL_GLYPH_MAX);

        log_info("/* %s */", __func__);

        log_info("is_locale_utf8: %s", yes_no(is_locale_utf8()));

        dump_glyph(SPECIAL_GLYPH_TREE_VERTICAL);
        dump_glyph(SPECIAL_GLYPH_TREE_BRANCH);
        dump_glyph(SPECIAL_GLYPH_TREE_RIGHT);
        dump_glyph(SPECIAL_GLYPH_TREE_SPACE);
        dump_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET);
        dump_glyph(SPECIAL_GLYPH_BLACK_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_WHITE_CIRCLE);
        dump_glyph(SPECIAL_GLYPH_MULTIPLICATION_SIGN);
        dump_glyph(SPECIAL_GLYPH_CIRCLE_ARROW);
        dump_glyph(SPECIAL_GLYPH_BULLET);
        dump_glyph(SPECIAL_GLYPH_ARROW);
        dump_glyph(SPECIAL_GLYPH_ELLIPSIS);
        dump_glyph(SPECIAL_GLYPH_MU);
        dump_glyph(SPECIAL_GLYPH_CHECK_MARK);
        dump_glyph(SPECIAL_GLYPH_CROSS_MARK);
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
}

int main(int argc, char *argv[]) {
        test_get_locales();
        test_locale_is_valid();
        test_locale_is_installed();
        test_keymaps();

        dump_special_glyphs();

        return 0;
}
