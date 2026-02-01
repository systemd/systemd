/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "journald-syslog.h"
#include "syslog-util.h"
#include "tests.h"

static void test_syslog_parse_identifier_one(
                const char *str,
                const char *ident,
                pid_t pid,
                const char *rest,
                int ret) {

        const char *buf = str;
        _cleanup_free_ char *ident2 = NULL;
        pid_t pid2;
        int ret2;

        ret2 = syslog_parse_identifier(&buf, &ident2, &pid2);

        ASSERT_EQ(ret, ret2);
        ASSERT_STREQ(ident, ident2);
        ASSERT_EQ(pid, pid2);
        ASSERT_STREQ(buf, rest);
}

static void test_syslog_parse_priority_one(const char *str, bool with_facility, int priority, int ret) {
        int priority2 = 0, ret2;

        ret2 = syslog_parse_priority(&str, &priority2, with_facility);

        assert_se(ret == ret2);
        if (ret2 == 1)
                assert_se(priority == priority2);
}

TEST(syslog_parse_identifier) {
        test_syslog_parse_identifier_one("pidu[111]: xxx", "pidu", 111, "xxx", 11);
        test_syslog_parse_identifier_one("pidu: xxx", "pidu", 0, "xxx", 6);
        test_syslog_parse_identifier_one("pidu:  xxx", "pidu", 0, " xxx", 6);
        test_syslog_parse_identifier_one("pidu xxx", NULL, 0, "pidu xxx", 0);
        test_syslog_parse_identifier_one("   pidu xxx", NULL, 0, "   pidu xxx", 0);
        test_syslog_parse_identifier_one("", NULL, 0, "", 0);
        test_syslog_parse_identifier_one("  ", NULL, 0, "  ", 0);
        test_syslog_parse_identifier_one(":", "", 0, "", 1);
        test_syslog_parse_identifier_one(":  ", "", 0, " ", 2);
        test_syslog_parse_identifier_one(" :", "", 0, "", 2);
        test_syslog_parse_identifier_one("   pidu:", "pidu", 0, "", 8);
        test_syslog_parse_identifier_one("pidu:", "pidu", 0, "", 5);
        test_syslog_parse_identifier_one("pidu: ", "pidu", 0, "", 6);
        test_syslog_parse_identifier_one("pidu : ", NULL, 0, "pidu : ", 0);
}

TEST(syslog_parse_priority) {
        test_syslog_parse_priority_one("", false, 0, 0);
        test_syslog_parse_priority_one("<>", false, 0, 0);
        test_syslog_parse_priority_one("<>aaa", false, 0, 0);
        test_syslog_parse_priority_one("<aaaa>", false, 0, 0);
        test_syslog_parse_priority_one("<aaaa>aaa", false, 0, 0);
        test_syslog_parse_priority_one(" <aaaa>", false, 0, 0);
        test_syslog_parse_priority_one(" <aaaa>aaa", false, 0, 0);
        test_syslog_parse_priority_one(" <aaaa>aaa", false, 0, 0);
        test_syslog_parse_priority_one(" <1>", false, 0, 0);
        test_syslog_parse_priority_one("<1>", false, 1, 1);
        test_syslog_parse_priority_one("<7>", false, 7, 1);
        test_syslog_parse_priority_one("<8>", false, 0, 0);
        test_syslog_parse_priority_one("<9>", true, 9, 1);
        test_syslog_parse_priority_one("<22>", true, 22, 1);
        test_syslog_parse_priority_one("<111>", false, 0, 0);
        test_syslog_parse_priority_one("<111>", true, 111, 1);
}

DEFINE_TEST_MAIN(LOG_INFO);
