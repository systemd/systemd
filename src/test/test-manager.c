/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "manager.h"
#include "tests.h"

TEST(manager_taint_string) {
        Manager m = {};

        _cleanup_free_ char *a = manager_taint_string(&m);
        assert_se(a);
        log_debug("taint string w/o split-usr: '%s'", a);
        /* split-usr is the only one that is cached in Manager, so we know it's not present.
         * The others are queried dynamically, so we'd need to duplicate the logic here
         * to test for them. Let's do just one. */
        assert_se(!strstr(a, "split-usr"));

        if (cg_all_unified() == 0)
                assert_se(strstr(a, "cgroupsv1"));
        else
                assert_se(!strstr(a, "cgroupsv1"));

        m.taint_usr = true;
        _cleanup_free_ char *b = manager_taint_string(&m);
        assert_se(b);
        log_debug("taint string w/ split-usr: '%s'", b);
        assert_se(strstr(b, "split-usr"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
