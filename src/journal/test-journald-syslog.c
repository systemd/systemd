/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "journald-manager.h"
#include "journald-syslog.h"
#include "path-util.h"
#include "rm-rf.h"
#include "syslog-util.h"
#include "tests.h"
#include "tmpfile-util.h"

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

TEST(syslog_socket_replaces_existing_event_source) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *old_source = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ char *syslog_socket = NULL;
        Manager m = {
                .syslog_fd = -EBADF,
        };

        ASSERT_OK(sd_event_new(&event));
        m.event = event;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-journald-syslog-XXXXXX", &tmpdir));
        syslog_socket = path_join(tmpdir, "dev-log");
        ASSERT_NOT_NULL(syslog_socket);

        ASSERT_OK(manager_open_syslog_socket(&m, syslog_socket));
        old_source = sd_event_source_ref(m.syslog_event_source);
        ASSERT_NOT_NULL(old_source);

        ASSERT_OK(manager_open_syslog_socket(&m, syslog_socket));
        ASSERT_OK_ZERO(sd_event_source_get_enabled(old_source, /* ret= */ NULL));
        ASSERT_TRUE(m.syslog_event_source != old_source);

        m.syslog_event_source = sd_event_source_unref(m.syslog_event_source);
        m.syslog_fd = safe_close(m.syslog_fd);
}

DEFINE_TEST_MAIN(LOG_INFO);
