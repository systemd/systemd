/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "macro.h"
#include "signal-util.h"

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

static void test_sigrtmin(void) {
        assert_se(sigrtmin == SIGRTMIN);
}

static void test_sigrtmax(void) {
        assert_se(sigrtmax == SIGRTMAX);
}

static int test_sigrtmin_comparisons_orig(int i) {
        /* The purpose of this function is to look at the disassembly
         * to check if sigrtmin is handled at least semi-efficiently. */
        return
                i == SIGINT ||
                i == SIGRTMIN+5 ||
                i == SIGRTMIN+6 ||
                i == SIGRTMIN+15 ||
                i == SIGRTMIN+16;
}

static int test_sigrtmin_comparisons(int i) {
        /* The purpose of this function is to look at the disassembly
         * to check if sigrtmin is handled at least semi-efficiently. */
        return
                i == SIGINT ||
                i == sigrtmin+5 ||
                i == sigrtmin+6 ||
                i == sigrtmin+15 ||
                i == sigrtmin+16;
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_block_signals();
        test_ignore_signals();
        test_sigrtmin();
        test_sigrtmax();
        log_debug("test_sigrtmin_comparisons → %d, %d",
                  test_sigrtmin_comparisons_orig(argc),
                  test_sigrtmin_comparisons(argc));

        return 0;
}
