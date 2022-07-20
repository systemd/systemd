/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "localed-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

TEST(find_language_fallback) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        assert_se(find_language_fallback("foobar", &ans) == 0);
        assert_se(ans == NULL);

        assert_se(find_language_fallback("csb", &ans) == 0);
        assert_se(ans == NULL);

        assert_se(find_language_fallback("csb_PL", &ans) == 1);
        assert_se(streq(ans, "csb:pl"));

        assert_se(find_language_fallback("szl_PL", &ans2) == 1);
        assert_se(streq(ans2, "szl:pl"));
}

TEST(find_converted_keymap) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;
        int r;

        assert_se(find_converted_keymap("pl", "foobar", &ans) == 0);
        assert_se(ans == NULL);

        r = find_converted_keymap("pl", NULL, &ans);
        if (r == 0) {
                log_info("Skipping rest of %s: keymaps are not installed", __func__);
                return;
        }

        assert_se(r == 1);
        assert_se(streq(ans, "pl"));

        assert_se(find_converted_keymap("pl", "dvorak", &ans2) == 1);
        assert_se(streq(ans2, "pl-dvorak"));
}

TEST(find_legacy_keymap) {
        Context c = {};
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        c.x11_layout = (char*) "foobar";
        assert_se(find_legacy_keymap(&c, &ans) == 0);
        assert_se(ans == NULL);

        c.x11_layout = (char*) "pl";
        assert_se(find_legacy_keymap(&c, &ans) == 1);
        assert_se(streq(ans, "pl2"));

        c.x11_layout = (char*) "pl,ru";
        assert_se(find_legacy_keymap(&c, &ans2) == 1);
        assert_se(streq(ans, "pl2"));
}

TEST(vconsole_convert_to_x11) {
        _cleanup_(context_clear) Context c = {};

        log_info("/* test emptying first (:) */");
        assert_se(free_and_strdup(&c.x11_layout, "foo") >= 0);
        assert_se(free_and_strdup(&c.x11_variant, "bar") >= 0);
        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(c.x11_layout == NULL);
        assert_se(c.x11_variant == NULL);

        log_info("/* test emptying second (:) */");

        assert_se(vconsole_convert_to_x11(&c) == 0);
        assert_se(c.x11_layout == NULL);
        assert_se(c.x11_variant == NULL);

        log_info("/* test without variant, new mapping (es:) */");
        assert_se(free_and_strdup(&c.vc_keymap, "es") >= 0);

        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(streq(c.x11_layout, "es"));
        assert_se(c.x11_variant == NULL);

        log_info("/* test with known variant, new mapping (es:dvorak) */");
        assert_se(free_and_strdup(&c.vc_keymap, "es-dvorak") >= 0);

        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(streq(c.x11_layout, "es"));
        assert_se(streq(c.x11_variant, "dvorak"));

        log_info("/* test with old mapping (fr:latin9) */");
        assert_se(free_and_strdup(&c.vc_keymap, "fr-latin9") >= 0);

        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(streq(c.x11_layout, "fr"));
        assert_se(streq(c.x11_variant, "latin9"));

        log_info("/* test with a compound mapping (ru,us) */");
        assert_se(free_and_strdup(&c.vc_keymap, "ru") >= 0);

        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(streq(c.x11_layout, "ru,us"));
        assert_se(c.x11_variant == NULL);

        log_info("/* test with a simple mapping (us) */");
        assert_se(free_and_strdup(&c.vc_keymap, "us") >= 0);

        assert_se(vconsole_convert_to_x11(&c) == 1);
        assert_se(streq(c.x11_layout, "us"));
        assert_se(c.x11_variant == NULL);
}

TEST(x11_convert_to_vconsole) {
        _cleanup_(context_clear) Context c = {};
        int r;

        log_info("/* test emptying first (:) */");
        assert_se(free_and_strdup(&c.vc_keymap, "foobar") >= 0);
        assert_se(x11_convert_to_vconsole(&c) == 1);
        assert_se(c.vc_keymap == NULL);

        log_info("/* test emptying second (:) */");

        assert_se(x11_convert_to_vconsole(&c) == 0);
        assert_se(c.vc_keymap == NULL);

        log_info("/* test without variant, new mapping (es:) */");
        assert_se(free_and_strdup(&c.x11_layout, "es") >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 1);
        assert_se(streq(c.vc_keymap, "es"));

        log_info("/* test with unknown variant, new mapping (es:foobar) */");
        assert_se(free_and_strdup(&c.x11_variant, "foobar") >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 0);
        assert_se(streq(c.vc_keymap, "es"));

        log_info("/* test with known variant, new mapping (es:dvorak) */");
        assert_se(free_and_strdup(&c.x11_variant, "dvorak") >= 0);

        r = x11_convert_to_vconsole(&c);
        if (r == 0) {
                log_info("Skipping rest of %s: keymaps are not installed", __func__);
                return;
        }

        assert_se(r == 1);
        assert_se(streq(c.vc_keymap, "es-dvorak"));

        log_info("/* test with old mapping (fr:latin9) */");
        assert_se(free_and_strdup(&c.x11_layout, "fr") >= 0);
        assert_se(free_and_strdup(&c.x11_variant, "latin9") >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 1);
        assert_se(streq(c.vc_keymap, "fr-latin9"));

        log_info("/* test with a compound mapping (us,ru:) */");
        assert_se(free_and_strdup(&c.x11_layout, "us,ru") >= 0);
        assert_se(free_and_strdup(&c.x11_variant, NULL) >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 1);
        assert_se(streq(c.vc_keymap, "us"));

        log_info("/* test with a compound mapping (ru,us:) */");
        assert_se(free_and_strdup(&c.x11_layout, "ru,us") >= 0);
        assert_se(free_and_strdup(&c.x11_variant, NULL) >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 1);
        assert_se(streq(c.vc_keymap, "ru"));

        /* https://bugzilla.redhat.com/show_bug.cgi?id=1333998 */
        log_info("/* test with a simple new mapping (ru:) */");
        assert_se(free_and_strdup(&c.x11_layout, "ru") >= 0);
        assert_se(free_and_strdup(&c.x11_variant, NULL) >= 0);

        assert_se(x11_convert_to_vconsole(&c) == 0);
        assert_se(streq(c.vc_keymap, "ru"));
}

static int intro(void) {
        _cleanup_free_ char *map = NULL;

        assert_se(get_testdata_dir("test-keymap-util/kbd-model-map", &map) >= 0);
        assert_se(setenv("SYSTEMD_KBD_MODEL_MAP", map, 1) == 0);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
