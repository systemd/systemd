/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "nulstr-util.h"
#include "strv.h"
#include "tests.h"

TEST(strv_split_nulstr) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "str0\0str1\0str2\0str3\0";

        l = strv_split_nulstr(nulstr);
        assert_se(l);

        assert_se(streq(l[0], "str0"));
        assert_se(streq(l[1], "str1"));
        assert_se(streq(l[2], "str2"));
        assert_se(streq(l[3], "str3"));
}

TEST(strv_parse_nulstr) {
        _cleanup_strv_free_ char **l = NULL;
        const char nulstr[] = "hoge\0hoge2\0hoge3\0\0hoge5\0\0xxx";

        l = strv_parse_nulstr(nulstr, sizeof(nulstr)-1);
        assert_se(l);
        puts("Parse nulstr:");
        strv_print(l);

        assert_se(streq(l[0], "hoge"));
        assert_se(streq(l[1], "hoge2"));
        assert_se(streq(l[2], "hoge3"));
        assert_se(streq(l[3], ""));
        assert_se(streq(l[4], "hoge5"));
        assert_se(streq(l[5], ""));
        assert_se(streq(l[6], "xxx"));
}

DEFINE_TEST_MAIN(LOG_INFO);
