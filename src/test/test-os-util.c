/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "log.h"
#include "os-util.h"

static void test_path_is_os_tree(void) {
        assert_se(path_is_os_tree("/") > 0);
        assert_se(path_is_os_tree("/etc") == 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_path_is_os_tree();

        return 0;
}
