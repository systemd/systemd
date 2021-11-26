/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "log.h"
#include "os-util.h"
#include "tests.h"

TEST(path_is_os_tree) {
        assert_se(path_is_os_tree("/") > 0);
        assert_se(path_is_os_tree("/etc") == 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
