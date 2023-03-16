/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "udev-util.h"

static void test_udev_rule_parse_value_one(const char *in, const char *expected_value, int expected_retval) {
        _cleanup_free_ char *str = NULL;
        char *value = UINT_TO_PTR(0x12345678U);
        char *endpos = UINT_TO_PTR(0x87654321U);

        log_info("/* %s (%s, %s, %d) */", __func__, in, strnull(expected_value), expected_retval);

        assert_se(str = strdup(in));
        assert_se(udev_rule_parse_value(str, &value, &endpos) == expected_retval);
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
        }
}

TEST(udev_rule_parse_value) {
        /* input: "valid operand"
         * parsed: valid operand
         * use the following command to help generate textual C strings:
         * python3 -c 'import json; print(json.dumps(input()))' */
        test_udev_rule_parse_value_one("\"valid operand\"", "valid operand", 0);
        /* input: "va'l\'id\"op\"erand"
         * parsed: va'l\'id"op"erand */
        test_udev_rule_parse_value_one("\"va'l\\'id\\\"op\\\"erand\"", "va'l\\'id\"op\"erand", 0);
        test_udev_rule_parse_value_one("no quotes", NULL, -EINVAL);
        test_udev_rule_parse_value_one("\"\\\\a\\b\\x\\y\"", "\\\\a\\b\\x\\y", 0);
        test_udev_rule_parse_value_one("\"reject\0nul\"", NULL, -EINVAL);
        /* input: e"" */
        test_udev_rule_parse_value_one("e\"\"", "", 0);
        /* input: e"1234" */
        test_udev_rule_parse_value_one("e\"1234\"", "1234", 0);
        /* input: e"\"" */
        test_udev_rule_parse_value_one("e\"\\\"\"", "\"", 0);
        /* input: e"\ */
        test_udev_rule_parse_value_one("e\"\\", NULL, -EINVAL);
        /* input: e"\" */
        test_udev_rule_parse_value_one("e\"\\\"", NULL, -EINVAL);
        /* input: e"\\" */
        test_udev_rule_parse_value_one("e\"\\\\\"", "\\", 0);
        /* input: e"\\\" */
        test_udev_rule_parse_value_one("e\"\\\\\\\"", NULL, -EINVAL);
        /* input: e"\\\"" */
        test_udev_rule_parse_value_one("e\"\\\\\\\"\"", "\\\"", 0);
        /* input: e"\\\\" */
        test_udev_rule_parse_value_one("e\"\\\\\\\\\"", "\\\\", 0);
        /* input: e"operand with newline\n" */
        test_udev_rule_parse_value_one("e\"operand with newline\\n\"", "operand with newline\n", 0);
        /* input: e"single\rcharacter\t\aescape\bsequence" */
        test_udev_rule_parse_value_one(
                "e\"single\\rcharacter\\t\\aescape\\bsequence\"", "single\rcharacter\t\aescape\bsequence", 0);
        /* input: e"reject\invalid escape sequence" */
        test_udev_rule_parse_value_one("e\"reject\\invalid escape sequence", NULL, -EINVAL);
        /* input: e"\ */
        test_udev_rule_parse_value_one("e\"\\", NULL, -EINVAL);
        /* input: "s\u1d1c\u1d04\u029c \u1d1c\u0274\u026a\u1d04\u1d0f\u1d05\u1d07 \U0001d568\U0001d560\U0001d568" */
        test_udev_rule_parse_value_one(
                "e\"s\\u1d1c\\u1d04\\u029c \\u1d1c\\u0274\\u026a\\u1d04\\u1d0f\\u1d05\\u1d07 \\U0001d568\\U0001d560\\U0001d568\"",
                "s\xe1\xb4\x9c\xe1\xb4\x84\xca\x9c \xe1\xb4\x9c\xc9\xb4\xc9\xaa\xe1\xb4\x84\xe1\xb4\x8f\xe1\xb4\x85\xe1\xb4\x87 \xf0\x9d\x95\xa8\xf0\x9d\x95\xa0\xf0\x9d\x95\xa8",
                0);
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

static void test_udev_resolve_subsys_kernel_one(const char *str, bool read_value, int retval, const char *expected) {
        char result[PATH_MAX] = "";
        int r;

        r = udev_resolve_subsys_kernel(str, result, sizeof(result), read_value);
        log_info("\"%s\" → expect: \"%s\", %d, actual: \"%s\", %d", str, strnull(expected), retval, result, r);
        assert_se(r == retval);
        if (r >= 0)
                assert_se(streq(result, expected));
}

TEST(udev_resolve_subsys_kernel) {
        test_udev_resolve_subsys_kernel_one("hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/foo", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/]", false, -EINVAL, NULL);

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

TEST(devpath_conflict) {
        assert_se(!devpath_conflict(NULL, NULL));
        assert_se(!devpath_conflict(NULL, "/devices/pci0000:00/0000:00:1c.4"));
        assert_se(!devpath_conflict("/devices/pci0000:00/0000:00:1c.4", NULL));
        assert_se(!devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:00.0"));
        assert_se(!devpath_conflict("/devices/virtual/net/veth99", "/devices/virtual/net/veth999"));

        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:1c.4"));
        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4", "/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0"));
        assert_se(devpath_conflict("/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0/nvme0n1",
                                   "/devices/pci0000:00/0000:00:1c.4/0000:3c:00.0/nvme/nvme0/nvme0n1/nvme0n1p1"));
}

DEFINE_TEST_MAIN(LOG_INFO);
