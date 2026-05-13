/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "clock-util.h"
#include "taint.h"
#include "tests.h"

TEST(taint_string) {
        _cleanup_free_ char *a = taint_string();
        assert_se(a);
        log_debug("taint string: '%s'", a);

        assert_se(!!strstr(a, "local-hwclock") == (clock_is_localtime(NULL) > 0));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
