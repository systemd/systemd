/* SPDX-License-Identifier: LGPL-2.1+ */

#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "macro.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "process-util.h"

#define info(sig) log_info(#sig " = " STRINGIFY(sig) " = %d", sig)

static void test_rt_signals(void) {
        info(SIGRTMIN);
        info(SIGRTMAX);

        /* We use signals SIGRTMIN+0 to SIGRTMIN+24 unconditionally */
        assert(SIGRTMAX - SIGRTMIN >= 24);
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

static void test_signal_from_string(void) {
        char buf[STRLEN("RTMIN+") + DECIMAL_STR_MAX(int) + 1];

        test_signal_to_string_one(SIGHUP);
        test_signal_to_string_one(SIGTERM);
        test_signal_to_string_one(SIGRTMIN);
        test_signal_to_string_one(SIGRTMIN + 3);
        test_signal_to_string_one(SIGRTMAX - 4);

        test_signal_from_string_one("RTMIN", SIGRTMIN);
        test_signal_from_string_one("RTMAX", SIGRTMAX);

        xsprintf(buf, "RTMIN+%d", SIGRTMAX - SIGRTMIN);
        test_signal_from_string_one(buf, SIGRTMAX);

        xsprintf(buf, "RTMIN+%d", INT_MAX);
        test_signal_from_string_one(buf, -ERANGE);

        xsprintf(buf, "RTMAX-%d", SIGRTMAX - SIGRTMIN);
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

static void test_block_signals(void) {
        sigset_t ss;

        assert_se(sigprocmask(0, NULL, &ss) >= 0);

        assert_se(sigismember(&ss, SIGUSR1) == 0);
        assert_se(sigismember(&ss, SIGALRM) == 0);
        assert_se(sigismember(&ss, SIGVTALRM) == 0);

        {
                BLOCK_SIGNALS(SIGUSR1, SIGVTALRM);

                assert_se(sigprocmask(0, NULL, &ss) >= 0);
                assert_se(sigismember(&ss, SIGUSR1) == 1);
                assert_se(sigismember(&ss, SIGALRM) == 0);
                assert_se(sigismember(&ss, SIGVTALRM) == 1);
        }

        assert_se(sigprocmask(0, NULL, &ss) >= 0);
        assert_se(sigismember(&ss, SIGUSR1) == 0);
        assert_se(sigismember(&ss, SIGALRM) == 0);
        assert_se(sigismember(&ss, SIGVTALRM) == 0);
}

static void test_ignore_signals(void) {
        assert_se(ignore_signals(SIGINT, -1) >= 0);
        assert_se(kill(getpid_cached(), SIGINT) >= 0);
        assert_se(ignore_signals(SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE, -1) >= 0);
        assert_se(kill(getpid_cached(), SIGUSR1) >= 0);
        assert_se(kill(getpid_cached(), SIGUSR2) >= 0);
        assert_se(kill(getpid_cached(), SIGTERM) >= 0);
        assert_se(kill(getpid_cached(), SIGPIPE) >= 0);
        assert_se(default_signals(SIGINT, SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE, -1) >= 0);
}

int main(int argc, char *argv[]) {
        test_rt_signals();
        test_signal_from_string();
        test_block_signals();
        test_ignore_signals();

        return 0;
}
