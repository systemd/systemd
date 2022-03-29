/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "log.h"
#include "specifier.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "unit-file.h"

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

        COMMON_CREDS_SPECIFIERS(LOOKUP_SCOPE_USER),
        { 'h', specifier_user_home,       NULL },

        COMMON_TMP_SPECIFIERS,
        {}
};

TEST(specifier_printf) {
        static const Specifier table[] = {
                { 'X', specifier_string,         (char*) "AAAA" },
                { 'Y', specifier_string,         (char*) "BBBB" },
                { 'e', specifier_string,         NULL           },
                COMMON_SYSTEM_SPECIFIERS,
                {}
        };

        _cleanup_free_ char *w = NULL;
        int r;

        r = specifier_printf("xxx a=%X b=%Y e=%e yyy", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);

        puts(w);
        assert_se(streq(w, "xxx a=AAAA b=BBBB e= yyy"));

        free(w);
        r = specifier_printf("machine=%m, boot=%b, host=%H, pretty=%R, version=%v, arch=%a, empty=%e", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r >= 0);
        assert_se(w);
        puts(w);

        w = mfree(w);
        specifier_printf("os=%o, os-version=%w, build=%B, variant=%W, empty=%e%e%e", SIZE_MAX, table, NULL, NULL, &w);
        if (w)
                puts(w);
}

TEST(specifier_real_path) {
        static const Specifier table[] = {
                { 'p', specifier_string,         "/dev/initctl" },
                { 'y', specifier_real_path,      "/dev/initctl" },
                { 'Y', specifier_real_directory, "/dev/initctl" },
                { 'w', specifier_real_path,      "/dev/tty" },
                { 'W', specifier_real_directory, "/dev/tty" },
                {}
        };

        _cleanup_free_ char *w = NULL;
        int r;

        r = specifier_printf("p=%p y=%y Y=%Y w=%w W=%W", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r >= 0 || r == -ENOENT);
        assert_se(w || r == -ENOENT);
        puts(strnull(w));

        /* /dev/initctl should normally be a symlink to /run/initctl */
        if (files_same("/dev/initctl", "/run/initctl", 0) > 0)
                assert_se(streq(w, "p=/dev/initctl y=/run/initctl Y=/run w=/dev/tty W=/dev"));
}

TEST(specifier_real_path_missing_file) {
        static const Specifier table[] = {
                { 'p', specifier_string,         "/dev/-no-such-file--" },
                { 'y', specifier_real_path,      "/dev/-no-such-file--" },
                { 'Y', specifier_real_directory, "/dev/-no-such-file--" },
                {}
        };

        _cleanup_free_ char *w = NULL;
        int r;

        r = specifier_printf("p=%p y=%y", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r == -ENOENT);

        r = specifier_printf("p=%p Y=%Y", SIZE_MAX, table, NULL, NULL, &w);
        assert_se(r == -ENOENT);
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

TEST(specifiers_missing_data_ok) {
        _cleanup_free_ char *resolved = NULL;

        assert_se(setenv("SYSTEMD_OS_RELEASE", "/dev/null", 1) == 0);
        assert_se(specifier_printf("%A-%B-%M-%o-%w-%W", SIZE_MAX, specifier_table, NULL, NULL, &resolved) >= 0);
        assert_se(streq(resolved, "-----"));

        assert_se(setenv("SYSTEMD_OS_RELEASE", "/nosuchfileordirectory", 1) == 0);
        assert_se(specifier_printf("%A-%B-%M-%o-%w-%W", SIZE_MAX, specifier_table, NULL, NULL, &resolved) == -EUNATCH);
        assert_se(streq(resolved, "-----"));

        assert_se(unsetenv("SYSTEMD_OS_RELEASE") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
