/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "tests.h"

TEST(strlen8) {
        assert_se(strlen8(NULL) == 0);
        assert_se(strlen8("") == 0);
        assert_se(strlen8("1") == 1);
        assert_se(strlen8("11") == 2);
        assert_se(strlen8("123456789") == 9);
        assert_se(strlen8("12\0004") == 2);
}

TEST(strlen16) {
        assert_se(strlen16(NULL) == 0);
        assert_se(strlen16(u"") == 0);
        assert_se(strlen16(u"1") == 1);
        assert_se(strlen16(u"11") == 2);
        assert_se(strlen16(u"123456789") == 9);
        assert_se(strlen16(u"12\0004") == 2);
}

TEST(strnlen8) {
        assert_se(strnlen8(NULL, 0) == 0);
        assert_se(strnlen8(NULL, 10) == 0);
        assert_se(strnlen8("", 10) == 0);
        assert_se(strnlen8("1", 10) == 1);
        assert_se(strnlen8("11", 1) == 1);
        assert_se(strnlen8("123456789", 7) == 7);
        assert_se(strnlen8("12\0004", 5) == 2);
}

TEST(strnlen16) {
        assert_se(strnlen16(NULL, 0) == 0);
        assert_se(strnlen16(NULL, 10) == 0);
        assert_se(strnlen16(u"", 10) == 0);
        assert_se(strnlen16(u"1", 10) == 1);
        assert_se(strnlen16(u"11", 1) == 1);
        assert_se(strnlen16(u"123456789", 7) == 7);
        assert_se(strnlen16(u"12\0004", 5) == 2);
}

DEFINE_TEST_MAIN(LOG_INFO);
