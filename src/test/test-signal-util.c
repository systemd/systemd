/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "log.h"
#include "macro.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"
#include "process-util.h"

#define info(sig) log_info(#sig " = " STRINGIFY(sig) " = %d", sig)

TEST(rt_signals) {
        info(SIGRTMIN);
        info(SIGRTMAX);

        /* We use signals SIGRTMIN+0 to SIGRTMIN+24 unconditionally */
        assert_se(SIGRTMAX - SIGRTMIN >= 24);
}

static void test_signal_to_string_one(int val) {
        const char *p;

        assert_se(p = signal_to_string(val));

        assert_se(signal_from_string(p) == val);

        p = strjoina("SIG", p);
        assert_se(signal_from_string(p) == val);
}

static void test_signal_from_string_one(const char *s, int val) {
        const char *p;

        assert_se(signal_from_string(s) == val);

        p = strjoina("SIG", s);
        assert_se(signal_from_string(p) == val);
}

static void test_signal_from_string_number(const char *s, int val) {
        const char *p;

        assert_se(signal_from_string(s) == val);

        p = strjoina("SIG", s);
        assert_se(signal_from_string(p) == -EINVAL);
}

TEST(signal_from_string) {
        char buf[STRLEN("RTMIN+") + DECIMAL_STR_MAX(int) + 1];

        test_signal_to_string_one(SIGHUP);
        test_signal_to_string_one(SIGTERM);
        test_signal_to_string_one(SIGRTMIN);
        test_signal_to_string_one(SIGRTMIN+3);
        test_signal_to_string_one(SIGRTMAX-4);

        test_signal_from_string_one("RTMIN", SIGRTMIN);
        test_signal_from_string_one("RTMAX", SIGRTMAX);

        xsprintf(buf, "RTMIN+%d", SIGRTMAX-SIGRTMIN);
        test_signal_from_string_one(buf, SIGRTMAX);

        xsprintf(buf, "RTMIN+%d", INT_MAX);
        test_signal_from_string_one(buf, -ERANGE);

        xsprintf(buf, "RTMAX-%d", SIGRTMAX-SIGRTMIN);
        test_signal_from_string_one(buf, SIGRTMIN);

        xsprintf(buf, "RTMAX-%d", INT_MAX);
        test_signal_from_string_one(buf, -ERANGE);

        test_signal_from_string_one("", -EINVAL);
        test_signal_from_string_one("hup", -EINVAL);
        test_signal_from_string_one("HOGEHOGE", -EINVAL);

        test_signal_from_string_one("RTMIN-5", -EINVAL);
        test_signal_from_string_one("RTMIN-    5", -EINVAL);
        test_signal_from_string_one("RTMIN    -5", -EINVAL);
        test_signal_from_string_one("RTMIN+    5", -EINVAL);
        test_signal_from_string_one("RTMIN    +5", -EINVAL);
        test_signal_from_string_one("RTMIN+100", -ERANGE);
        test_signal_from_string_one("RTMIN+-3", -EINVAL);
        test_signal_from_string_one("RTMIN++3", -EINVAL);
        test_signal_from_string_one("RTMIN+HUP", -EINVAL);
        test_signal_from_string_one("RTMIN3", -EINVAL);

        test_signal_from_string_one("RTMAX+5", -EINVAL);
        test_signal_from_string_one("RTMAX+    5", -EINVAL);
        test_signal_from_string_one("RTMAX    +5", -EINVAL);
        test_signal_from_string_one("RTMAX-    5", -EINVAL);
        test_signal_from_string_one("RTMAX    -5", -EINVAL);
        test_signal_from_string_one("RTMAX-100", -ERANGE);
        test_signal_from_string_one("RTMAX-+3", -EINVAL);
        test_signal_from_string_one("RTMAX--3", -EINVAL);
        test_signal_from_string_one("RTMAX-HUP", -EINVAL);

        test_signal_from_string_number("3", 3);
        test_signal_from_string_number("+5", 5);
        test_signal_from_string_number("  +5", 5);
        test_signal_from_string_number("10000", -ERANGE);
        test_signal_from_string_number("-2", -ERANGE);
}

TEST(block_signals) {
        ASSERT_EQ(signal_is_blocked(SIGUSR1), 0);
        ASSERT_EQ(signal_is_blocked(SIGALRM), 0);
        ASSERT_EQ(signal_is_blocked(SIGVTALRM), 0);

        {
                BLOCK_SIGNALS(SIGUSR1, SIGVTALRM);

                ASSERT_GT(signal_is_blocked(SIGUSR1), 0);
                ASSERT_EQ(signal_is_blocked(SIGALRM), 0);
                ASSERT_GT(signal_is_blocked(SIGVTALRM), 0);
        }

        ASSERT_EQ(signal_is_blocked(SIGUSR1), 0);
        ASSERT_EQ(signal_is_blocked(SIGALRM), 0);
        ASSERT_EQ(signal_is_blocked(SIGVTALRM), 0);
}

TEST(ignore_signals) {
        ASSERT_OK(ignore_signals(SIGINT));
        ASSERT_OK(kill(getpid_cached(), SIGINT));
        ASSERT_OK(ignore_signals(SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE));
        ASSERT_OK(kill(getpid_cached(), SIGUSR1));
        ASSERT_OK(kill(getpid_cached(), SIGUSR2));
        ASSERT_OK(kill(getpid_cached(), SIGTERM));
        ASSERT_OK(kill(getpid_cached(), SIGPIPE));
        ASSERT_OK(default_signals(SIGINT, SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE));
}

TEST(pop_pending_signal) {

        ASSERT_EQ(signal_is_blocked(SIGUSR1), 0);
        ASSERT_EQ(signal_is_blocked(SIGUSR2), 0);
        ASSERT_EQ(pop_pending_signal(SIGUSR1), 0);
        ASSERT_EQ(pop_pending_signal(SIGUSR2), 0);

        {
                BLOCK_SIGNALS(SIGUSR1, SIGUSR2);

                ASSERT_GT(signal_is_blocked(SIGUSR1), 0);
                ASSERT_GT(signal_is_blocked(SIGUSR2), 0);

                ASSERT_EQ(pop_pending_signal(SIGUSR1), 0);
                ASSERT_EQ(pop_pending_signal(SIGUSR2), 0);

                ASSERT_OK(raise(SIGUSR1));

                ASSERT_EQ(pop_pending_signal(SIGUSR2), 0);
                assert_se(pop_pending_signal(SIGUSR1) == SIGUSR1);
                ASSERT_EQ(pop_pending_signal(SIGUSR1), 0);

                ASSERT_OK(raise(SIGUSR1));
                ASSERT_OK(raise(SIGUSR2));

                assert_cc(SIGUSR1 < SIGUSR2);

                assert_se(pop_pending_signal(SIGUSR1, SIGUSR2) == SIGUSR1);
                assert_se(pop_pending_signal(SIGUSR1, SIGUSR2) == SIGUSR2);
                ASSERT_EQ(pop_pending_signal(SIGUSR1, SIGUSR2), 0);
        }

        ASSERT_EQ(signal_is_blocked(SIGUSR1), 0);
        ASSERT_EQ(signal_is_blocked(SIGUSR2), 0);
        ASSERT_EQ(pop_pending_signal(SIGUSR1), 0);
        ASSERT_EQ(pop_pending_signal(SIGUSR2), 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
