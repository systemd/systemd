/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "log.h"
#include "specifier.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_specifier_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *x = NULL;

        x = specifier_escape(a);
        assert_se(streq_ptr(x, b));
}

TEST(specifier_escape) {
        test_specifier_escape_one(NULL, NULL);
        test_specifier_escape_one("", "");
        test_specifier_escape_one("%", "%%");
        test_specifier_escape_one("foo bar", "foo bar");
        test_specifier_escape_one("foo%bar", "foo%%bar");
        test_specifier_escape_one("%%%%%", "%%%%%%%%%%");
}

static void test_specifier_escape_strv_one(char **a, char **b) {
        _cleanup_strv_free_ char **x = NULL;

        assert_se(specifier_escape_strv(a, &x) >= 0);
        assert_se(strv_equal(x, b));
}

TEST(specifier_escape_strv) {
        test_specifier_escape_strv_one(NULL, NULL);
        test_specifier_escape_strv_one(STRV_MAKE(NULL), STRV_MAKE(NULL));
        test_specifier_escape_strv_one(STRV_MAKE(""), STRV_MAKE(""));
        test_specifier_escape_strv_one(STRV_MAKE("foo"), STRV_MAKE("foo"));
        test_specifier_escape_strv_one(STRV_MAKE("%"), STRV_MAKE("%%"));
        test_specifier_escape_strv_one(STRV_MAKE("foo", "%", "foo%", "%foo", "foo%foo", "quux", "%%%"),
                                       STRV_MAKE("foo", "%%", "foo%%", "%%foo", "foo%%foo", "quux", "%%%%%%"));
}

/* Any specifier functions which don't need an argument. */
static const Specifier specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,

        COMMON_CREDS_SPECIFIERS,
        { 'h', specifier_user_home,       NULL },

        COMMON_TMP_SPECIFIERS,
        {}
};

TEST(specifier_printf) {
        static const Specifier table[] = {
                { 'X', specifier_string,         (char*) "AAAA" },
                { 'Y', specifier_string,         (char*) "BBBB" },
                COMMON_SYSTEM_SPECIFIERS,
                {}
        };

        _cleanup_free_ char *w = NULL;
        int r;

        r = specifier_printf("xxx a=%X b=%Y yyy", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);

        puts(w);
        assert_se(streq(w, "xxx a=AAAA b=BBBB yyy"));

        free(w);
        r = specifier_printf("machine=%m, boot=%b, host=%H, version=%v, arch=%a", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);
        puts(w);

        w = mfree(w);
        specifier_printf("os=%o, os-version=%w, build=%B, variant=%W", SIZE_MAX, table, NULL, NULL, &w);
        if (w)
                puts(w);
}

TEST(specifiers) {
        for (const Specifier *s = specifier_table; s->specifier; s++) {
                char spec[3];
                _cleanup_free_ char *resolved = NULL;

                xsprintf(spec, "%%%c", s->specifier);

                assert_se(specifier_printf(spec, SIZE_MAX, specifier_table, NULL, NULL, &resolved) >= 0);

                log_info("%%%c → %s", s->specifier, resolved);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
