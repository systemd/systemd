/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"
#include "udev-util.h"

static void test_udev_rule_parse_value_one(const char *in, const char *expected_value, int expected_retval) {
        _cleanup_free_ char *str = NULL;
        char *value = UINT_TO_PTR(0x12345678U);
        char *endpos = UINT_TO_PTR(0x87654321U);

        assert_se(str = strdup(in));
        assert_se(udev_rule_parse_value(str, &value, &endpos) == expected_retval);
        if (expected_retval < 0) {
                /* not modified on failure */
                assert_se(value == UINT_TO_PTR(0x12345678U));
                assert_se(endpos == UINT_TO_PTR(0x87654321U));
        } else {
                assert_se(streq_ptr(value, expected_value));
                assert_se(endpos == str + strlen(in));
        }
}

static void test_parse_value(void) {
        /* input: "valid operand"
         * parsed: valid operand
         * use the following command to help generate textual C strings:
         * python3 -c 'import json; print(json.dumps(input()))' */
        test_udev_rule_parse_value_one(
                "\"valid operand\"",
                "valid operand",
                0
        );
}

static void test_parse_value_with_backslashes(void) {
        /* input: "va'l\'id\"op\"erand"
         * parsed: va'l\'id"op"erand */
        test_udev_rule_parse_value_one(
                "\"va'l\\'id\\\"op\\\"erand\"",
                "va'l\\'id\"op\"erand",
                0
        );
}

static void test_parse_value_no_quotes(void) {
        test_udev_rule_parse_value_one(
                "no quotes",
                0,
                -EINVAL
        );
}

static void test_parse_value_noescape(void) {
        test_udev_rule_parse_value_one(
                "\"\\\\a\\b\\x\\y\"",
                "\\\\a\\b\\x\\y",
                0
        );
}

static void test_parse_value_nul(void) {
        test_udev_rule_parse_value_one(
                "\"reject\0nul\"",
                0,
                -EINVAL
        );
}

static void test_parse_value_escape_nothing(void) {
        /* input: e"" */
        test_udev_rule_parse_value_one(
                "e\"\"",
                "",
                0
        );
}

static void test_parse_value_escape_nothing2(void) {
        /* input: e"1234" */
        test_udev_rule_parse_value_one(
                "e\"1234\"",
                "1234",
                0
        );
}

static void test_parse_value_escape_double_quote(void) {
        /* input: e"\"" */
        test_udev_rule_parse_value_one(
                "e\"\\\"\"",
                "\"",
                0
        );
}

static void test_parse_value_escape_backslash(void) {
        /* input: e"\ */
        test_udev_rule_parse_value_one(
                "e\"\\",
                0,
                -EINVAL
        );
        /* input: e"\" */
        test_udev_rule_parse_value_one(
                "e\"\\\"",
                0,
                -EINVAL
        );
        /* input: e"\\" */
        test_udev_rule_parse_value_one(
                "e\"\\\\\"",
                "\\",
                0
        );
        /* input: e"\\\" */
        test_udev_rule_parse_value_one(
                "e\"\\\\\\\"",
                0,
                -EINVAL
        );
        /* input: e"\\\"" */
        test_udev_rule_parse_value_one(
                "e\"\\\\\\\"\"",
                "\\\"",
                0
        );
        /* input: e"\\\\" */
        test_udev_rule_parse_value_one(
                "e\"\\\\\\\\\"",
                "\\\\",
                0
        );
}

static void test_parse_value_newline(void) {
        /* input: e"operand with newline\n" */
        test_udev_rule_parse_value_one(
                "e\"operand with newline\\n\"",
                "operand with newline\n",
                0
        );
}

static void test_parse_value_escaped(void) {
        /* input: e"single\rcharacter\t\aescape\bsequence" */
        test_udev_rule_parse_value_one(
                "e\"single\\rcharacter\\t\\aescape\\bsequence\"",
                "single\rcharacter\t\aescape\bsequence",
                0
        );
}

static void test_parse_value_invalid_escape(void) {
        /* input: e"reject\invalid escape sequence" */
        test_udev_rule_parse_value_one(
                "e\"reject\\invalid escape sequence",
                0,
                -EINVAL
        );
}

static void test_parse_value_invalid_termination(void) {
        /* input: e"\ */
        test_udev_rule_parse_value_one(
                "e\"\\",
                0,
                -EINVAL
        );
}

static void test_parse_value_unicode(void) {
        /* input: "s\u1d1c\u1d04\u029c \u1d1c\u0274\u026a\u1d04\u1d0f\u1d05\u1d07 \U0001d568\U0001d560\U0001d568" */
        test_udev_rule_parse_value_one(
                "e\"s\\u1d1c\\u1d04\\u029c \\u1d1c\\u0274\\u026a\\u1d04\\u1d0f\\u1d05\\u1d07 \\U0001d568\\U0001d560\\U0001d568\"",
                "s\xe1\xb4\x9c\xe1\xb4\x84\xca\x9c \xe1\xb4\x9c\xc9\xb4\xc9\xaa\xe1\xb4\x84\xe1\xb4\x8f\xe1\xb4\x85\xe1\xb4\x87 \xf0\x9d\x95\xa8\xf0\x9d\x95\xa0\xf0\x9d\x95\xa8",
                0
        );
}

static void test_udev_replace_whitespace_one_len(const char *str, size_t len, const char *expected) {
        _cleanup_free_ char *result = NULL;
        int r;

        result = new(char, len + 1);
        assert_se(result);
        r = udev_replace_whitespace(str, result, len);
        assert_se((size_t) r == strlen(expected));
        assert_se(streq(result, expected));
}

static void test_udev_replace_whitespace_one(const char *str, const char *expected) {
        test_udev_replace_whitespace_one_len(str, strlen(str), expected);
}

static void test_udev_replace_whitespace(void) {
        log_info("/* %s */", __func__);

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

static void test_udev_resolve_subsys_kernel_one(const char *str, bool read_value, int retval, const char *expected) {
        char result[PATH_MAX] = "";
        int r;

        r = udev_resolve_subsys_kernel(str, result, sizeof(result), read_value);
        log_info("\"%s\" → expect: \"%s\", %d, actual: \"%s\", %d", str, strnull(expected), retval, result, r);
        assert_se(r == retval);
        if (r >= 0)
                assert_se(streq(result, expected));
}

static void test_udev_resolve_subsys_kernel(void) {
        log_info("/* %s */", __func__);

        test_udev_resolve_subsys_kernel_one("hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/foo", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/]", false, -ENODEV, NULL);

        test_udev_resolve_subsys_kernel_one("[net/lo]", false, 0, "/sys/devices/virtual/net/lo");
        test_udev_resolve_subsys_kernel_one("[net/lo]/", false, 0, "/sys/devices/virtual/net/lo");
        test_udev_resolve_subsys_kernel_one("[net/lo]hoge", false, 0, "/sys/devices/virtual/net/lo/hoge");
        test_udev_resolve_subsys_kernel_one("[net/lo]/hoge", false, 0, "/sys/devices/virtual/net/lo/hoge");

        test_udev_resolve_subsys_kernel_one("[net/lo]", true, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[net/lo]/", true, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[net/lo]hoge", true, 0, "");
        test_udev_resolve_subsys_kernel_one("[net/lo]/hoge", true, 0, "");
        test_udev_resolve_subsys_kernel_one("[net/lo]address", true, 0, "00:00:00:00:00:00");
        test_udev_resolve_subsys_kernel_one("[net/lo]/address", true, 0, "00:00:00:00:00:00");
}

int main(int argc, char **argv) {
        test_parse_value();
        test_parse_value_with_backslashes();
        test_parse_value_no_quotes();
        test_parse_value_nul();
        test_parse_value_noescape();

        test_parse_value_escape_nothing();
        test_parse_value_escape_nothing2();
        test_parse_value_escape_double_quote();
        test_parse_value_escape_backslash();
        test_parse_value_newline();
        test_parse_value_escaped();
        test_parse_value_invalid_escape();
        test_parse_value_invalid_termination();
        test_parse_value_unicode();

        test_udev_replace_whitespace();
        test_udev_resolve_subsys_kernel();

        return EXIT_SUCCESS;
}
