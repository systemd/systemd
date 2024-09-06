/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "import-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

static void test_import_url_last_component_one(const char *input, const char *output, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(import_url_last_component(input, &s) == ret);
        ASSERT_STREQ(output, s);
}

TEST(import_url_last_component) {
        test_import_url_last_component_one("https://foobar/waldo/quux", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/", "waldo", 0);
        test_import_url_last_component_one("https://foobar/", NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("https://foobar", NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("https://foobar/waldo/quux?foo=bar", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/?foo=bar", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/?foo=bar#piep", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/quux/#piep", "quux", 0);
        test_import_url_last_component_one("https://foobar/waldo/quux#piep", "quux", 0);
        test_import_url_last_component_one("https://", NULL, -EINVAL);
        test_import_url_last_component_one("", NULL, -EINVAL);
        test_import_url_last_component_one(":", NULL, -EINVAL);
        test_import_url_last_component_one(":/", NULL, -EINVAL);
        test_import_url_last_component_one("x:/", NULL, -EINVAL);
        test_import_url_last_component_one("x:y", NULL, -EADDRNOTAVAIL);
        test_import_url_last_component_one("x:y/z", "z", 0);
}

static void test_import_url_change_suffix_one(const char *input, size_t n, const char *suffix, const char *output, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(import_url_change_suffix(input, n, suffix, &s) == ret);
        ASSERT_STREQ(output, s);
}

TEST(import_url_change_suffix) {
        test_import_url_change_suffix_one("https://foobar/waldo/quux", 1, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/", 1, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux///?mief", 1, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux///?mief#opopo", 1, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff", 2, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff/", 2, "wuff", "https://foobar/waldo/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff", 0, "wuff", "https://foobar/waldo/quux/quff/wuff", 0);
        test_import_url_change_suffix_one("https://foobar/waldo/quux/quff?aa?bb##4", 0, "wuff", "https://foobar/waldo/quux/quff/wuff", 0);
        test_import_url_change_suffix_one("https://", 0, "wuff", NULL, -EINVAL);
        test_import_url_change_suffix_one("", 0, "wuff", NULL, -EINVAL);
        test_import_url_change_suffix_one(":", 0, "wuff", NULL, -EINVAL);
        test_import_url_change_suffix_one(":/", 0, "wuff", NULL, -EINVAL);
        test_import_url_change_suffix_one("x:/", 0, "wuff", NULL, -EINVAL);
        test_import_url_change_suffix_one("x:y", 0, "wuff", "x:y/wuff", 0);
        test_import_url_change_suffix_one("x:y/z", 0, "wuff", "x:y/z/wuff", 0);
        test_import_url_change_suffix_one("x:y/z/", 0, "wuff", "x:y/z/wuff", 0);
        test_import_url_change_suffix_one("x:y/z/", 1, "wuff", "x:y/wuff", 0);
        test_import_url_change_suffix_one("x:y/z/", 2, "wuff", "x:y/wuff", 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
