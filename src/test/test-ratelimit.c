/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "macro.h"
#include "ratelimit.h"
#include "time-util.h"

static void test_ratelimit_below(void) {
        int i;
        RateLimit ratelimit = { 1 * USEC_PER_SEC, 10 };

        for (i = 0; i < 10; i++)
                assert_se(ratelimit_below(&ratelimit));
        assert_se(!ratelimit_below(&ratelimit));
        sleep(1);
        for (i = 0; i < 10; i++)
                assert_se(ratelimit_below(&ratelimit));

        ratelimit = (RateLimit) { 0, 10 };
        for (i = 0; i < 10000; i++)
                assert_se(ratelimit_below(&ratelimit));
}

int main(int argc, char *argv[]) {
        test_ratelimit_below();

        return 0;
}
