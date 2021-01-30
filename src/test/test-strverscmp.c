/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "strv.h"
#include "strverscmp.h"
#include "tests.h"

static void test_strverscmp_improved_one(const char *newer, const char *older) {
        log_info("/* %s(%s, %s) */", __func__, strnull(newer), strnull(older));

        assert_se(strverscmp_improved(newer, newer) == 0);
        assert_se(strverscmp_improved(newer, older) >  0);
        assert_se(strverscmp_improved(older, newer) <  0);
        assert_se(strverscmp_improved(older, older) == 0);
}

static void test_strverscmp_improved(void) {
        static const char * const versions[] = {
                "",
                "~1",
                "ab",
                "abb",
                "abc",
                "0001",
                "002",
                "12",
                "122",
                "122.9",
                "123~rc1",
                "123",
                "123-a",
                "123-a.1",
                "123-a1",
                "123-a1.1",
                "123-3",
                "123-3.1",
                "123^patch1",
                "123^1",
                "123.a-1"
                "123.1-1",
                "123a-1",
                "124",
                NULL,
        };
        const char * const *p, * const *q;

        STRV_FOREACH(p, versions)
                STRV_FOREACH(q, p + 1)
                        test_strverscmp_improved_one(*q, *p);

        test_strverscmp_improved_one("123.45-67.89", "123.45-67.88");
        test_strverscmp_improved_one("123.45-67.89a", "123.45-67.89");
        test_strverscmp_improved_one("123.45-67.89", "123.45-67.ab");
        test_strverscmp_improved_one("123.45-67.89", "123.45-67.9");
        test_strverscmp_improved_one("123.45-67.89", "123.45-67");
        test_strverscmp_improved_one("123.45-67.89", "123.45-66.89");
        test_strverscmp_improved_one("123.45-67.89", "123.45-9.99");
        test_strverscmp_improved_one("123.45-67.89", "123.42-99.99");
        test_strverscmp_improved_one("123.45-67.89", "123-99.99");

        /* '~' : pre-releases */
        test_strverscmp_improved_one("123.45-67.89", "123~rc1-99.99");
        test_strverscmp_improved_one("123-45.67.89", "123~rc1-99.99");
        test_strverscmp_improved_one("123~rc2-67.89", "123~rc1-99.99");
        test_strverscmp_improved_one("123^aa2-67.89", "123~rc1-99.99");
        test_strverscmp_improved_one("123aa2-67.89", "123~rc1-99.99");

        /* '-' : separator between version and release. */
        test_strverscmp_improved_one("123.45-67.89", "123-99.99");
        test_strverscmp_improved_one("123^aa2-67.89", "123-99.99");
        test_strverscmp_improved_one("123aa2-67.89", "123-99.99");

        /* '^' : patch releases */
        test_strverscmp_improved_one("123.45-67.89", "123^45-67.89");
        test_strverscmp_improved_one("123^aa2-67.89", "123^aa1-99.99");
        test_strverscmp_improved_one("123aa2-67.89", "123^aa2-67.89");

        /* '.' : point release */
        test_strverscmp_improved_one("123aa2-67.89", "123.aa2-67.89");
        test_strverscmp_improved_one("123.ab2-67.89", "123.aa2-67.89");

        /* invalid characters */
        assert_se(strverscmp_improved("123_aa2-67.89", "123aa+2-67.89") == 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_strverscmp_improved();

        return 0;
}
