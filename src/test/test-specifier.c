/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "log.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_specifier_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *x = NULL;

        x = specifier_escape(a);
        assert_se(streq_ptr(x, b));
}

static void test_specifier_escape(void) {
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

static void test_specifier_escape_strv(void) {
        test_specifier_escape_strv_one(NULL, NULL);
        test_specifier_escape_strv_one(STRV_MAKE(NULL), STRV_MAKE(NULL));
        test_specifier_escape_strv_one(STRV_MAKE(""), STRV_MAKE(""));
        test_specifier_escape_strv_one(STRV_MAKE("foo"), STRV_MAKE("foo"));
        test_specifier_escape_strv_one(STRV_MAKE("%"), STRV_MAKE("%%"));
        test_specifier_escape_strv_one(STRV_MAKE("foo", "%", "foo%", "%foo", "foo%foo", "quux", "%%%"),
                                       STRV_MAKE("foo", "%%", "foo%%", "%%foo", "foo%%foo", "quux", "%%%%%%"));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_specifier_escape();
        test_specifier_escape_strv();

        return 0;
}
