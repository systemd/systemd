/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "clock-util.h"
#include "taint.h"
#include "tests.h"

TEST(taint_string) {
        _cleanup_free_ char *a = ASSERT_NOT_NULL(taint_string());
        log_debug("taint string: '%s'", a);

        ASSERT_EQ(!!strstr(a, "local-hwclock"), clock_is_localtime(/* adjtime_path= */ NULL) > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
