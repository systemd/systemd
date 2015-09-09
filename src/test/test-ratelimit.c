/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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

#include <unistd.h>

#include "ratelimit.h"
#include "time-util.h"
#include "macro.h"

static void test_ratelimit_test(void) {
        int i;
        RATELIMIT_DEFINE(ratelimit, 1 * USEC_PER_SEC, 10);

        for (i = 0; i < 10; i++)
                assert_se(ratelimit_test(&ratelimit));
        assert_se(!ratelimit_test(&ratelimit));
        sleep(1);
        for (i = 0; i < 10; i++)
                assert_se(ratelimit_test(&ratelimit));

        RATELIMIT_INIT(ratelimit, 0, 10);
        for (i = 0; i < 10000; i++)
                assert_se(ratelimit_test(&ratelimit));
}

int main(int argc, char *argv[]) {
        test_ratelimit_test();

        return 0;
}
