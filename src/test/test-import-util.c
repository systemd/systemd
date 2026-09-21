/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "import-util.h"
#include "tests.h"

static void test_import_url_last_component_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(import_url_last_component(input, &s) == ret);
        ASSERT_STREQ(output, s);
}

TEST(import_url_last_component) {
        test_import_url_last_component_one("https://foobar/waldo/quux", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/", "waldo", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/", /* output= */ NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("https://foobar", /* output= */ NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("https://foobar/waldo/quux?foo=bar", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/?foo=bar", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/?foo=bar#piep", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/#piep", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://foobar/waldo/quux#piep", "quux", /* ret= */ 0);
        test_import_url_last_component_one("https://", /* output= */ NULL, -EINVAL);
        test_import_url_last_component_one("", /* output= */ NULL, -EINVAL);
        test_import_url_last_component_one(":", /* output= */ NULL, -EINVAL);
        test_import_url_last_component_one(":/", /* output= */ NULL, -EINVAL);
        test_import_url_last_component_one("x:/", /* output= */ NULL, -EINVAL);
        test_import_url_last_component_one("x:y", /* output= */ NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("x:y/z", "z", /* ret= */ 0);
}

static void test_import_url_change_suffix_one(const char *input, size_t n, const char *suffix, const char *output, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(import_url_change_suffix(input, n, suffix, &s) == ret);
        ASSERT_STREQ(output, s);
}

TEST(import_url_change_suffix) {
        test_import_url_change_suffix_one("https://foobar/waldo/quux", 1, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/", 1, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux///?mief", 1, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux///?mief#opopo", 1, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff", 2, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff/", 2, "wuff", "https://foobar/waldo/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff", 0, "wuff", "https://foobar/waldo/quux/quff/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff?aa?bb##4", 0, "wuff", "https://foobar/waldo/quux/quff/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("https://", 0, "wuff", /* output= */ NULL, -EINVAL);
        test_import_url_change_suffix_one("", 0, "wuff", /* output= */ NULL, -EINVAL);
        test_import_url_change_suffix_one(":", 0, "wuff", /* output= */ NULL, -EINVAL);
        test_import_url_change_suffix_one(":/", 0, "wuff", /* output= */ NULL, -EINVAL);
        test_import_url_change_suffix_one("x:/", 0, "wuff", /* output= */ NULL, -EINVAL);
        test_import_url_change_suffix_one("x:y", 0, "wuff", "x:y/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("x:y/z", 0, "wuff", "x:y/z/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("x:y/z/", 0, "wuff", "x:y/z/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("x:y/z/", 1, "wuff", "x:y/wuff", /* ret= */ 0);
        test_import_url_change_suffix_one("x:y/z/", 2, "wuff", "x:y/wuff", /* ret= */ 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
