/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "localed-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

TEST(find_language_fallback) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        ASSERT_OK_ZERO(find_language_fallback("foobar", &ans));
        ASSERT_NULL(ans);

        ASSERT_OK_ZERO(find_language_fallback("csb", &ans));
        ASSERT_NULL(ans);

        ASSERT_OK_POSITIVE(find_language_fallback("csb_PL", &ans));
        ASSERT_STREQ(ans, "csb:pl");

        ASSERT_OK_POSITIVE(find_language_fallback("szl_PL", &ans2));
        ASSERT_STREQ(ans2, "szl:pl");
}

TEST(find_converted_keymap) {
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;
        int r;

        ASSERT_OK_ZERO(find_converted_keymap(
                        &(X11Context) {
                                .layout  = (char*) "pl",
                                .variant = (char*) "foobar",
                        }, &ans));
        ASSERT_NULL(ans);

        ASSERT_OK(r = find_converted_keymap(
                        &(X11Context) {
                                .layout  = (char*) "pl",
                        }, &ans));
        if (r == 0)
                return (void) log_tests_skipped("keymaps are not installed");

        ASSERT_STREQ(ans, "pl");
        ans = mfree(ans);

        ASSERT_OK_POSITIVE(find_converted_keymap(
                        &(X11Context) {
                                .layout  = (char*) "pl",
                                .variant = (char*) "dvorak",
                        }, &ans2));
        ASSERT_STREQ(ans2, "pl-dvorak");
}

TEST(find_legacy_keymap) {
        X11Context xc = {};
        _cleanup_free_ char *ans = NULL, *ans2 = NULL;

        xc.layout = (char*) "foobar";
        ASSERT_OK_ZERO(find_legacy_keymap(&xc, &ans));
        ASSERT_NULL(ans);

        xc.layout = (char*) "pl";
        ASSERT_OK_POSITIVE(find_legacy_keymap(&xc, &ans));
        ASSERT_STREQ(ans, "pl2");

        xc.layout = (char*) "pl,ru";
        ASSERT_OK_POSITIVE(find_legacy_keymap(&xc, &ans2));
        ASSERT_STREQ(ans, "pl2");
}

TEST(vconsole_convert_to_x11) {
        _cleanup_(x11_context_clear) X11Context xc = {};
        _cleanup_(vc_context_clear) VCContext vc = {};
        int r;

        log_info("/* test empty keymap */");
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_TRUE(x11_context_isempty(&xc));

        log_info("/* test without variant, new mapping (es:) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "es"));
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "es");
        ASSERT_NULL(xc.variant);
        x11_context_clear(&xc);

        log_info("/* test with known variant, new mapping (es:dvorak) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "es-dvorak"));
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "es");
        ASSERT_STREQ(xc.variant, "dvorak");
        x11_context_clear(&xc);

        log_info("/* test with old mapping (fr:latin9) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "fr-latin9"));
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "fr");
        ASSERT_STREQ(xc.variant, "latin9");
        x11_context_clear(&xc);

        log_info("/* test with a compound mapping (ru,us) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "ru"));
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "ru,us");
        ASSERT_NULL(xc.variant);
        x11_context_clear(&xc);

        log_info("/* test with a simple mapping (us) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "us"));
        ASSERT_OK(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "us");
        ASSERT_NULL(xc.variant);
        x11_context_clear(&xc);

        /* "gh" has no mapping in kbd-model-map and kbd provides a converted keymap for this layout. */
        log_info("/* test with a converted keymap (gh:) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "gh"));
        ASSERT_OK(r = vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        if (r == 0)
                return (void) log_tests_skipped("keymaps are not installed");

        ASSERT_STREQ(xc.layout, "gh");
        ASSERT_NULL(xc.variant);
        x11_context_clear(&xc);

        log_info("/* test with converted keymap and with a known variant (gh:ewe) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "gh-ewe"));
        ASSERT_OK_POSITIVE(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "gh");
        ASSERT_STREQ(xc.variant, "ewe");
        x11_context_clear(&xc);

        log_info("/* test with converted keymap and with an unknown variant (gh:ewe) */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "gh-foobar"));
        ASSERT_OK_POSITIVE(vconsole_convert_to_x11(&vc, x11_context_verify, &xc));
        ASSERT_STREQ(xc.layout, "gh");
        ASSERT_NULL(xc.variant);
        x11_context_clear(&xc);
}

TEST(x11_convert_to_vconsole) {
        _cleanup_(x11_context_clear) X11Context xc = {};
        _cleanup_(vc_context_clear) VCContext vc = {};

        log_info("/* test empty layout (:) */");
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_TRUE(vc_context_isempty(&vc));

        log_info("/* test without variant, new mapping (es:) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "es"));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "es");
        vc_context_clear(&vc);

        log_info("/* test with unknown variant, new mapping (es:foobar) */");
        ASSERT_OK(free_and_strdup(&xc.variant, "foobar"));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "es");
        vc_context_clear(&vc);

        log_info("/* test with known variant, new mapping (es:dvorak) */");
        ASSERT_OK(free_and_strdup(&xc.variant, "dvorak"));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        if (vc_context_isempty(&vc)) {
                log_info("Skipping rest of %s: keymaps are not installed", __func__);
                return;
        }
        ASSERT_STREQ(vc.keymap, "es-dvorak");
        vc_context_clear(&vc);

        /* es no-variant test is not very good as the desired match
        comes first in the list so will win if both candidates score
        the same. in this case the desired match comes second so will
        not win unless we correctly give the no-variant match a bonus
        */
        log_info("/* test without variant, desired match second (bg,us:) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "bg,us"));
        ASSERT_OK(free_and_strdup(&xc.variant, NULL));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "bg_bds-utf8");
        vc_context_clear(&vc);

        /* same, but with variant specified as "," */
        log_info("/* test with variant as ',', desired match second (bg,us:) */");
        ASSERT_OK(free_and_strdup(&xc.variant, ","));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "bg_bds-utf8");
        vc_context_clear(&vc);

        log_info("/* test with old mapping (fr:latin9) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "fr"));
        ASSERT_OK(free_and_strdup(&xc.variant, "latin9"));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "fr-latin9");
        vc_context_clear(&vc);

        /* https://bugzilla.redhat.com/show_bug.cgi?id=1039185 */
        /* us,ru is the x config users want, but they still want ru
        as the console layout in this case */
        log_info("/* test with a compound mapping (us,ru:) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "us,ru"));
        ASSERT_OK(free_and_strdup(&xc.variant, NULL));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "ru");
        vc_context_clear(&vc);

        log_info("/* test with a compound mapping (ru,us:) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "ru,us"));
        ASSERT_OK(free_and_strdup(&xc.variant, NULL));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "ru");
        vc_context_clear(&vc);

        /* https://bugzilla.redhat.com/show_bug.cgi?id=1333998 */
        log_info("/* test with a simple new mapping (ru:) */");
        ASSERT_OK(free_and_strdup(&xc.layout, "ru"));
        ASSERT_OK(free_and_strdup(&xc.variant, NULL));
        ASSERT_OK(x11_convert_to_vconsole(&xc, &vc));
        ASSERT_STREQ(vc.keymap, "ru");
}

static int intro(void) {
        _cleanup_free_ char *map = NULL;

        ASSERT_OK(get_testdata_dir("test-keymap-util/kbd-model-map", &map));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_KBD_MODEL_MAP", map, /* overwrite = */ true));

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
