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

        return EXIT_SUCCESS;
}
