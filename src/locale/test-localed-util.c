/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "fileio.h"
#include "localed-util.h"
#include "log.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

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

        log_info("/* test leading-dash keymap */");
        ASSERT_OK(free_and_strdup(&vc.keymap, "-foo"));
        ASSERT_ERROR(vconsole_convert_to_x11(&vc, x11_context_verify, &xc), EINVAL);
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

        log_info("/* test leading-comma layout */");
        ASSERT_OK(free_and_strdup(&xc.layout, ",us"));
        ASSERT_ERROR(x11_convert_to_vconsole(&xc, &vc), EINVAL);
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
        if (vc_context_isempty(&vc))
                return (void) log_info("Skipping rest of %s: keymaps are not installed", __func__);

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

TEST(x11_context_normalize) {
        _cleanup_(x11_context_clear) X11Context xc = {};

        /* x11_read_data() parses 'Option "XkbVariant" ""' into a non-NULL
         * empty string. x11_context_normalize() converts empty strings back
         * to NULL (with freeing), so that x11_context_is_safe() and
         * x11_context_equal() treat them as unset. See issue #43007. */

        /* Empty fields are normalized to NULL. */
        ASSERT_OK(free_and_strdup(&xc.layout, "gb"));
        ASSERT_OK(free_and_strdup(&xc.variant, ""));
        ASSERT_OK(free_and_strdup(&xc.options, ""));
        x11_context_normalize(&xc);
        ASSERT_STREQ(xc.layout, "gb");
        ASSERT_NULL(xc.variant);
        ASSERT_NULL(xc.options);
        ASSERT_TRUE(x11_context_is_safe(&xc));
        ASSERT_OK(x11_context_verify(&xc));

        /* An empty layout leaves the context empty, not unsafe. */
        x11_context_clear(&xc);
        ASSERT_OK(free_and_strdup(&xc.layout, ""));
        x11_context_normalize(&xc);
        ASSERT_NULL(xc.layout);
        ASSERT_TRUE(x11_context_isempty(&xc));
}

TEST(locale_utf8_codeset_end) {
        /* Returns the position just after the codeset, i.e. the rest of the string. */
        ASSERT_STREQ(locale_utf8_codeset_end(".UTF-8"), "");
        ASSERT_STREQ(locale_utf8_codeset_end(".utf8"), "");
        ASSERT_STREQ(locale_utf8_codeset_end(".UTF-8@valencia"), "@valencia");
        ASSERT_STREQ(locale_utf8_codeset_end(".utf8@valencia"), "@valencia");

        /* Non-UTF-8 codesets, of any length and in any case. */
        ASSERT_NULL(locale_utf8_codeset_end(".ISO-8859-1"));
        ASSERT_NULL(locale_utf8_codeset_end(".eucKR"));
        ASSERT_NULL(locale_utf8_codeset_end(".UTF-16"));

        /* The codeset must end at the modifier or at the end of the string. */
        ASSERT_NULL(locale_utf8_codeset_end(".UTF-8foo"));
}

TEST(locale_strip_utf8_codeset) {
        _cleanup_free_ char *s = NULL;

        /* Names without codeset are copied as-is. */
        ASSERT_OK(locale_strip_utf8_codeset("sr_RS", &s));
        ASSERT_STREQ(s, "sr_RS");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("ca_ES@valencia", &s));
        ASSERT_STREQ(s, "ca_ES@valencia");
        s = mfree(s);

        /* The UTF-8 codeset is stripped in both of its spellings. */
        ASSERT_OK(locale_strip_utf8_codeset("sr_RS.UTF-8", &s));
        ASSERT_STREQ(s, "sr_RS");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("sr_RS.utf8", &s));
        ASSERT_STREQ(s, "sr_RS");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("C.UTF-8", &s));
        ASSERT_STREQ(s, "C");
        s = mfree(s);

        /* The codeset is stripped from before the modifier. */
        ASSERT_OK(locale_strip_utf8_codeset("ca_ES.UTF-8@valencia", &s));
        ASSERT_STREQ(s, "ca_ES@valencia");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("ca_ES.utf8@valencia", &s));
        ASSERT_STREQ(s, "ca_ES@valencia");
        s = mfree(s);

        /* A '.' after the modifier belongs to the modifier, not the codeset. */
        ASSERT_OK(locale_strip_utf8_codeset("sr_RS@latin.UTF-8", &s));
        ASSERT_STREQ(s, "sr_RS@latin.UTF-8");
        s = mfree(s);

        /* Non-UTF-8 codesets are kept, also when of the same length as ".UTF-8". */
        ASSERT_OK(locale_strip_utf8_codeset("ko_KR.eucKR", &s));
        ASSERT_STREQ(s, "ko_KR.eucKR");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("de_DE.ISO-8859-1", &s));
        ASSERT_STREQ(s, "de_DE.ISO-8859-1");
        s = mfree(s);

        ASSERT_OK(locale_strip_utf8_codeset("de_DE.ISO-8859-15@euro", &s));
        ASSERT_STREQ(s, "de_DE.ISO-8859-15@euro");
}

TEST(locale_gen_locale_supported) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *supported = NULL, *missing = NULL, *entry = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-localed-util.XXXXXX", &tmp));

        supported = path_join(tmp, "SUPPORTED");
        ASSERT_NOT_NULL(supported);

        missing = path_join(tmp, "nonexistent");
        ASSERT_NOT_NULL(missing);

        ASSERT_OK(write_string_file(supported,
                        "en_US.UTF-8 UTF-8\n"
                        "de_DE ISO-8859-1\n"
                        "sr_RS UTF-8\n"
                        "ca_ES@valencia UTF-8\n"
                        "\n"
                        "# comment\n",
                        WRITE_STRING_FILE_CREATE));

        /* Exact match, with the codeset in the listed name. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("en_US.UTF-8", supported, &entry));
        ASSERT_STREQ(entry, "en_US.UTF-8 UTF-8");
        entry = mfree(entry);

        /* The codeset spelling does not matter, as localedef normalizes it. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("en_US.utf8", supported, &entry));
        ASSERT_STREQ(entry, "en_US.UTF-8 UTF-8");
        entry = mfree(entry);

        /* Locale listed without the codeset, but requested with it. See issue #44823. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("sr_RS.UTF-8", supported, &entry));
        ASSERT_STREQ(entry, "sr_RS UTF-8");
        entry = mfree(entry);

        ASSERT_OK_POSITIVE(locale_gen_locale_supported("sr_RS.utf8", supported, &entry));
        ASSERT_STREQ(entry, "sr_RS UTF-8");
        entry = mfree(entry);

        /* Same, with a modifier. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("ca_ES.UTF-8@valencia", supported, &entry));
        ASSERT_STREQ(entry, "ca_ES@valencia UTF-8");
        entry = mfree(entry);

        /* The modifier must not be dropped when the codeset is stripped. */
        ASSERT_OK_ZERO(locale_gen_locale_supported("ca_ES.UTF-8", supported, &entry));
        ASSERT_NULL(entry);
        ASSERT_OK_ZERO(locale_gen_locale_supported("sr_RS.UTF-8@latin", supported, &entry));
        ASSERT_NULL(entry);

        /* Locale listed without the codeset, and requested without it, too. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("sr_RS", supported, &entry));
        ASSERT_STREQ(entry, "sr_RS UTF-8");
        entry = mfree(entry);

        /* A locale listed with the codeset must also be requested with it, as localedef
         * does not install it under the name without the codeset. */
        ASSERT_OK_ZERO(locale_gen_locale_supported("en_US", supported, &entry));
        ASSERT_NULL(entry);

        /* Locale names are compared case-insensitively. */
        ASSERT_OK_POSITIVE(locale_gen_locale_supported("SR_RS.UTF-8", supported, &entry));
        ASSERT_STREQ(entry, "sr_RS UTF-8");
        entry = mfree(entry);

        /* Locales only listed with a non-UTF-8 codeset are not supported. */
        ASSERT_OK_ZERO(locale_gen_locale_supported("de_DE", supported, &entry));
        ASSERT_NULL(entry);
        ASSERT_OK_ZERO(locale_gen_locale_supported("de_DE.UTF-8", supported, &entry));
        ASSERT_NULL(entry);

        /* Unknown locales are not supported. */
        ASSERT_OK_ZERO(locale_gen_locale_supported("xx_XX.UTF-8", supported, &entry));

        /* Locale templates without country code are never supported. */
        ASSERT_ERROR(locale_gen_locale_supported("en", supported, &entry), EINVAL);

        /* A missing SUPPORTED file cannot be used to check the locale. */
        ASSERT_ERROR(locale_gen_locale_supported("sr_RS.UTF-8", missing, &entry), EOPNOTSUPP);
}

static int intro(void) {
        _cleanup_free_ char *map = NULL;

        ASSERT_OK(get_testdata_dir("test-keymap-util/kbd-model-map", &map));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_KBD_MODEL_MAP", map, /* overwrite= */ true));

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
