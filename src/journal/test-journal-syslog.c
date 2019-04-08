/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "journald-syslog.h"
#include "macro.h"
#include "string-util.h"
#include "syslog-util.h"

static void test_syslog_parse_identifier(const char *str,
                                         const char *ident, const char *pid, const char *rest, int ret) {
        const char *buf = str;
        _cleanup_free_ char *ident2 = NULL, *pid2 = NULL;
        int ret2;

        ret2 = syslog_parse_identifier(&buf, &ident2, &pid2);

        assert_se(ret == ret2);
        assert_se(ident == ident2 || streq_ptr(ident, ident2));
        assert_se(pid == pid2 || streq_ptr(pid, pid2));
        assert_se(streq(buf, rest));
}

static void test_syslog_parse_priority(const char *str, int priority, int ret) {
        const char *buf = str;
        int priority2 = 0, ret2;

        ret2 = syslog_parse_priority(&buf, &priority2, false);

        assert_se(ret == ret2);
        if (ret2 == 1)
                assert_se(priority == priority2);
}

int main(void) {
        test_syslog_parse_identifier("pidu[111]: xxx", "pidu", "111", "xxx", 11);
        test_syslog_parse_identifier("pidu: xxx", "pidu", NULL, "xxx", 6);
        test_syslog_parse_identifier("pidu:  xxx", "pidu", NULL, " xxx", 6);
        test_syslog_parse_identifier("pidu xxx", NULL, NULL, "pidu xxx", 0);
        test_syslog_parse_identifier("   pidu xxx", NULL, NULL, "   pidu xxx", 0);
        test_syslog_parse_identifier("", NULL, NULL, "", 0);
        test_syslog_parse_identifier("  ", NULL, NULL, "  ", 0);
        test_syslog_parse_identifier(":", "", NULL, "", 1);
        test_syslog_parse_identifier(":  ", "", NULL, " ", 2);
        test_syslog_parse_identifier(" :", "", NULL, "", 2);
        test_syslog_parse_identifier("   pidu:", "pidu", NULL, "", 8);
        test_syslog_parse_identifier("pidu:", "pidu", NULL, "", 5);
        test_syslog_parse_identifier("pidu: ", "pidu", NULL, "", 6);
        test_syslog_parse_identifier("pidu : ", NULL, NULL, "pidu : ", 0);

        test_syslog_parse_priority("<>", 0, 0);
        test_syslog_parse_priority("<>aaa", 0, 0);
        test_syslog_parse_priority("<aaaa>", 0, 0);
        test_syslog_parse_priority("<aaaa>aaa", 0, 0);
        test_syslog_parse_priority(" <aaaa>", 0, 0);
        test_syslog_parse_priority(" <aaaa>aaa", 0, 0);
        /* TODO: add test cases of valid priorities */

        return 0;
}
