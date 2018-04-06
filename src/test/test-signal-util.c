/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "macro.h"
#include "signal-util.h"
#include "process-util.h"

#define info(sig) log_info(#sig " = " STRINGIFY(sig) " = %d", sig)

static void test_rt_signals(void) {
        info(SIGRTMIN);
        info(SIGRTMAX);

        /* We use signals SIGRTMIN+0 to SIGRTMIN+24 unconditionally */
        assert(SIGRTMAX - SIGRTMIN >= 24);
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
        test_block_signals();
        test_ignore_signals();

        return 0;
}
