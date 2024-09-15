/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "udev-rules.h"

static void test_udev_rule_parse_value_one(const char *in, const char *expected_value, bool expected_case_insensitive, int expected_retval) {
        _cleanup_free_ char *str = NULL;
        char *value = UINT_TO_PTR(0x12345678U);
        char *endpos = UINT_TO_PTR(0x87654321U);
        bool i;

        log_info("/* %s (%s, %s, %d) */", __func__, in, strnull(expected_value), expected_retval);

        assert_se(str = strdup(in));
        assert_se(udev_rule_parse_value(str, &value, &endpos, &i) == expected_retval);
        if (expected_retval < 0) {
                /* not modified on failure */
                assert_se(value == UINT_TO_PTR(0x12345678U));
                assert_se(endpos == UINT_TO_PTR(0x87654321U));
        } else {
                assert_se(streq_ptr(value, expected_value));
                assert_se(endpos == str + strlen(in));
                /*
                 * The return value must be terminated by two subsequent NULs
                 * so it could be safely interpreted as nulstr.
                 */
                assert_se(value[strlen(value) + 1] == '\0');
                assert_se(i == expected_case_insensitive);
        }
}

TEST(udev_rule_parse_value) {
        /* input: "valid operand"
         * parsed: valid operand
         * use the following command to help generate textual C strings:
         * python3 -c 'import json; print(json.dumps(input()))' */
        test_udev_rule_parse_value_one("\"valid operand\"", "valid operand", /* case_insensitive = */ false, 0);
        /* input: "va'l\'id\"op\"erand"
         * parsed: va'l\'id"op"erand */
        test_udev_rule_parse_value_one("\"va'l\\'id\\\"op\\\"erand\"", "va'l\\'id\"op\"erand", /* case_insensitive = */ false, 0);
        test_udev_rule_parse_value_one("no quotes", NULL, /* case_insensitive = */ false, -EINVAL);
        test_udev_rule_parse_value_one("\"\\\\a\\b\\x\\y\"", "\\\\a\\b\\x\\y", /* case_insensitive = */ false, 0);
        test_udev_rule_parse_value_one("\"reject\0nul\"", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: e"" */
        test_udev_rule_parse_value_one("e\"\"", "", /* case_insensitive = */ false, 0);
        /* input: e"1234" */
        test_udev_rule_parse_value_one("e\"1234\"", "1234", /* case_insensitive = */ false, 0);
        /* input: e"\"" */
        test_udev_rule_parse_value_one("e\"\\\"\"", "\"", /* case_insensitive = */ false, 0);
        /* input: e"\ */
        test_udev_rule_parse_value_one("e\"\\", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: e"\" */
        test_udev_rule_parse_value_one("e\"\\\"", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: e"\\" */
        test_udev_rule_parse_value_one("e\"\\\\\"", "\\", /* case_insensitive = */ false, 0);
        /* input: e"\\\" */
        test_udev_rule_parse_value_one("e\"\\\\\\\"", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: e"\\\"" */
        test_udev_rule_parse_value_one("e\"\\\\\\\"\"", "\\\"", /* case_insensitive = */ false, 0);
        /* input: e"\\\\" */
        test_udev_rule_parse_value_one("e\"\\\\\\\\\"", "\\\\", /* case_insensitive = */ false, 0);
        /* input: e"operand with newline\n" */
        test_udev_rule_parse_value_one("e\"operand with newline\\n\"", "operand with newline\n", /* case_insensitive = */ false, 0);
        /* input: e"single\rcharacter\t\aescape\bsequence" */
        test_udev_rule_parse_value_one(
                "e\"single\\rcharacter\\t\\aescape\\bsequence\"", "single\rcharacter\t\aescape\bsequence", /* case_insensitive = */ false, 0);
        /* input: e"reject\invalid escape sequence" */
        test_udev_rule_parse_value_one("e\"reject\\invalid escape sequence", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: e"\ */
        test_udev_rule_parse_value_one("e\"\\", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: "s\u1d1c\u1d04\u029c \u1d1c\u0274\u026a\u1d04\u1d0f\u1d05\u1d07 \U0001d568\U0001d560\U0001d568" */
        test_udev_rule_parse_value_one(
                "e\"s\\u1d1c\\u1d04\\u029c \\u1d1c\\u0274\\u026a\\u1d04\\u1d0f\\u1d05\\u1d07 \\U0001d568\\U0001d560\\U0001d568\"",
                "s\xe1\xb4\x9c\xe1\xb4\x84\xca\x9c \xe1\xb4\x9c\xc9\xb4\xc9\xaa\xe1\xb4\x84\xe1\xb4\x8f\xe1\xb4\x85\xe1\xb4\x87 \xf0\x9d\x95\xa8\xf0\x9d\x95\xa0\xf0\x9d\x95\xa8",
                /* case_insensitive = */ false, 0);
        /* input: i"ABCD1234" */
        test_udev_rule_parse_value_one("i\"ABCD1234\"", "ABCD1234", /* case_insensitive = */ true, 0);
        /* input: i"ABCD1234" */
        test_udev_rule_parse_value_one("e\"ABCD1234\"", "ABCD1234", /* case_insensitive = */ false, 0);
        /* input: ei"\\"ABCD1234 */
        test_udev_rule_parse_value_one("ei\"\\\\ABCD1234\"", "\\ABCD1234", /* case_insensitive = */ true, 0);
        /* input: ie"\\"ABCD1234 */
        test_udev_rule_parse_value_one("ie\"\\\\ABCD1234\"", "\\ABCD1234", /* case_insensitive = */ true, 0);
        /* input: i */
        test_udev_rule_parse_value_one("i", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: ee"" */
        test_udev_rule_parse_value_one("ee\"\"", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: iei"" */
        test_udev_rule_parse_value_one("iei\"\"", NULL, /* case_insensitive = */ false, -EINVAL);
        /* input: a"" */
        test_udev_rule_parse_value_one("a\"\"", NULL, /* case_insensitive = */ false, -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
