/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "recovery-key.h"
#include "tests.h"

static void test_normalize_recovery_key(const char *t, const char *expected) {
        _cleanup_free_ char *z = NULL;
        int r;

        ASSERT_NOT_NULL(t);

        r = normalize_recovery_key(t, &z);
        if (expected) {
                ASSERT_OK(r);
                ASSERT_STREQ(z, expected);
        } else {
                ASSERT_ERROR(r, EINVAL);
                ASSERT_NULL(z);
        }
}

TEST(normalize_recovery_key_all) {
        test_normalize_recovery_key("iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("iefgcelhbiduvkjvcjvuncnkvlfchdidjhtuhhdeurkllkegilkjgbrthjkbgktj",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("IEFGCELH-BIDUVKJV-CJVUNCNK-VLFCHDID-JHTUHHDE-URKLLKEG-ILKJGBRT-HJKBGKTJ",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("IEFGCELHBIDUVKJVCJVUNCNKVLFCHDIDJHTUHHDEURKLLKEGILKJGBRTHJKBGKTJ",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("Iefgcelh-Biduvkjv-Cjvuncnk-Vlfchdid-Jhtuhhde-Urkllkeg-Ilkjgbrt-Hjkbgktj",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("Iefgcelhbiduvkjvcjvuncnkvlfchdidjhtuhhdeurkllkegilkjgbrthjkbgktj",
                                    "iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj");

        test_normalize_recovery_key("iefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgkt", /* expected= */ NULL);
        test_normalize_recovery_key("iefgcelhbiduvkjvcjvuncnkvlfchdidjhtuhhdeurkllkegilkjgbrthjkbgkt", /* expected= */ NULL);
        test_normalize_recovery_key("IEFGCELHBIDUVKJVCJVUNCNKVLFCHDIDJHTUHHDEURKLLKEGILKJGBRTHJKBGKT", /* expected= */ NULL);

        test_normalize_recovery_key("xefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj", /* expected= */ NULL);
        test_normalize_recovery_key("Xefgcelh-biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj", /* expected= */ NULL);
        test_normalize_recovery_key("iefgcelh+biduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj", /* expected= */ NULL);
        test_normalize_recovery_key("iefgcelhebiduvkjv-cjvuncnk-vlfchdid-jhtuhhde-urkllkeg-ilkjgbrt-hjkbgktj", /* expected= */ NULL);

        test_normalize_recovery_key("", /* expected= */ NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
