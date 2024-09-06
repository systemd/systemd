/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "udev-util.h"

static void test_udev_replace_whitespace_one_len(const char *str, size_t len, const char *expected) {
        _cleanup_free_ char *result = NULL;
        int r;

        result = new(char, len + 1);
        assert_se(result);
        r = udev_replace_whitespace(str, result, len);
        assert_se((size_t) r == strlen(expected));
        ASSERT_STREQ(result, expected);
}

static void test_udev_replace_whitespace_one(const char *str, const char *expected) {
        test_udev_replace_whitespace_one_len(str, strlen(str), expected);
}

TEST(udev_replace_whitespace) {
        test_udev_replace_whitespace_one("hogehoge", "hogehoge");
        test_udev_replace_whitespace_one("hoge  hoge", "hoge_hoge");
        test_udev_replace_whitespace_one("  hoge  hoge  ", "hoge_hoge");
        test_udev_replace_whitespace_one("     ", "");
        test_udev_replace_whitespace_one("hoge ", "hoge");

        test_udev_replace_whitespace_one_len("hoge hoge    ", 9, "hoge_hoge");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 8, "hoge_hog");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 7, "hoge_ho");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 6, "hoge_h");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 5, "hoge");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 4, "hoge");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 3, "hog");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 2, "ho");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 1, "h");
        test_udev_replace_whitespace_one_len("hoge hoge    ", 0, "");

        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 16, "hoge_hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 15, "hoge_hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 14, "hoge_hog");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 13, "hoge_ho");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 12, "hoge_h");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 11, "hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 10, "hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 9, "hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 8, "hoge");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 7, "hog");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 6, "ho");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 5, "h");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 4, "");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 3, "");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 2, "");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 1, "");
        test_udev_replace_whitespace_one_len("    hoge   hoge    ", 0, "");
}

DEFINE_TEST_MAIN(LOG_INFO);
