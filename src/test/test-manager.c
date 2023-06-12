/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "manager.h"
#include "tests.h"

TEST(manager_taint_string) {
        Manager m = {};

        _cleanup_free_ char *a = manager_taint_string(&m);
        assert_se(a);
        log_debug("taint string: '%s'", a);

        if (cg_all_unified() == 0)
                assert_se(strstr(a, "cgroupsv1"));
        else
                assert_se(!strstr(a, "cgroupsv1"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
