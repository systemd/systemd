/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "manager.h"
#include "tests.h"

TEST(manager_taint_string) {
        Manager m = {};

        _cleanup_free_ char *a = manager_taint_string(&m);
        ASSERT_TRUE(a);
        log_debug("taint string: '%s'", a);

        if (cg_all_unified() == 0)
                ASSERT_TRUE(strstr(a, "cgroupsv1"));
        else
                ASSERT_FALSE(strstr(a, "cgroupsv1"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
