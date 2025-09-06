/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"

#define info(sig) log_info(#sig " = " STRINGIFY(sig) " = %d", sig)

TEST(rt_signals) {
        info(SIGRTMIN);
        info(SIGRTMAX);

        /* We use signals SIGRTMIN+0 to SIGRTMIN+29 unconditionally. SIGRTMIN+30 can be used only when
         * built with glibc. */
#ifdef __GLIBC__
        assert_se(SIGRTMAX - SIGRTMIN >= 30);
#else
        assert_se(SIGRTMAX - SIGRTMIN >= 29);
#endif
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
        assert_se(signal_is_blocked(SIGUSR1) == 0);
        assert_se(signal_is_blocked(SIGALRM) == 0);
        assert_se(signal_is_blocked(SIGVTALRM) == 0);

        {
                BLOCK_SIGNALS(SIGUSR1, SIGVTALRM);

                assert_se(signal_is_blocked(SIGUSR1) > 0);
                assert_se(signal_is_blocked(SIGALRM) == 0);
                assert_se(signal_is_blocked(SIGVTALRM) > 0);
        }

        assert_se(signal_is_blocked(SIGUSR1) == 0);
        assert_se(signal_is_blocked(SIGALRM) == 0);
        assert_se(signal_is_blocked(SIGVTALRM) == 0);
}

TEST(ignore_signals) {
        assert_se(ignore_signals(SIGINT) >= 0);
        assert_se(kill(getpid_cached(), SIGINT) >= 0);
        assert_se(ignore_signals(SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE) >= 0);
        assert_se(kill(getpid_cached(), SIGUSR1) >= 0);
        assert_se(kill(getpid_cached(), SIGUSR2) >= 0);
        assert_se(kill(getpid_cached(), SIGTERM) >= 0);
        assert_se(kill(getpid_cached(), SIGPIPE) >= 0);
        assert_se(default_signals(SIGINT, SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE) >= 0);
}

TEST(pop_pending_signal) {

        assert_se(signal_is_blocked(SIGUSR1) == 0);
        assert_se(signal_is_blocked(SIGUSR2) == 0);
        assert_se(pop_pending_signal(SIGUSR1) == 0);
        assert_se(pop_pending_signal(SIGUSR2) == 0);

        {
                BLOCK_SIGNALS(SIGUSR1, SIGUSR2);

                assert_se(signal_is_blocked(SIGUSR1) > 0);
                assert_se(signal_is_blocked(SIGUSR2) > 0);

                assert_se(pop_pending_signal(SIGUSR1) == 0);
                assert_se(pop_pending_signal(SIGUSR2) == 0);

                assert_se(raise(SIGUSR1) >= 0);

                assert_se(pop_pending_signal(SIGUSR2) == 0);
                assert_se(pop_pending_signal(SIGUSR1) == SIGUSR1);
                assert_se(pop_pending_signal(SIGUSR1) == 0);

                assert_se(raise(SIGUSR1) >= 0);
                assert_se(raise(SIGUSR2) >= 0);

                assert_cc(SIGUSR1 < SIGUSR2);

                assert_se(pop_pending_signal(SIGUSR1, SIGUSR2) == SIGUSR1);
                assert_se(pop_pending_signal(SIGUSR1, SIGUSR2) == SIGUSR2);
                assert_se(pop_pending_signal(SIGUSR1, SIGUSR2) == 0);
        }

        assert_se(signal_is_blocked(SIGUSR1) == 0);
        assert_se(signal_is_blocked(SIGUSR2) == 0);
        assert_se(pop_pending_signal(SIGUSR1) == 0);
        assert_se(pop_pending_signal(SIGUSR2) == 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
