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

int main(int argc, char *argv[]) {
        test_block_signals();
}
