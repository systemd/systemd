/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "log.h"
#include "os-util.h"
#include "tests.h"

static void test_path_is_os_tree(void) {
        assert_se(path_is_os_tree("/") > 0);
        assert_se(path_is_os_tree("/etc") == 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_path_is_os_tree();

        return 0;
}
