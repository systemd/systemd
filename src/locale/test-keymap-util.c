/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "keymap-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

static void test_find_language_fallback(void) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        log_info("/*** %s ***/", __func__);

        assert_se(find_language_fallback("foobar", &ans) == 0);
        assert_se(ans == NULL);

        assert_se(find_language_fallback("csb", &ans) == 0);
        assert_se(ans == NULL);

        assert_se(find_language_fallback("csb_PL", &ans) == 1);
        assert_se(streq(ans, "csb:pl"));

        assert_se(find_language_fallback("szl_PL", &ans2) == 1);
        assert_se(streq(ans2, "szl:pl"));
}

static void test_find_converted_keymap(void) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;
        int r;

        log_info("/*** %s ***/", __func__);

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

static void test_find_legacy_keymap(void) {
        Context c = {};
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        log_info("/*** %s ***/", __func__);

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

static void test_vconsole_convert_to_x11(void) {
        _cleanup_(context_clear) Context c = {};

        log_info("/*** %s ***/", __func__);

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

        assert_se(vconsole_convert_to_x11(&c) == 0); // FIXME
        assert_se(streq(c.x11_layout, "es"));
        assert_se(c.x11_variant == NULL); // FIXME: "dvorak"

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

static void test_x11_convert_to_vconsole(void) {
        _cleanup_(context_clear) Context c = {};
        int r;

        log_info("/*** %s ***/", __func__);

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

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_find_language_fallback();
        test_find_converted_keymap();
        test_find_legacy_keymap();

        test_vconsole_convert_to_x11();
        test_x11_convert_to_vconsole();

        return 0;
}
