/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "udev-builtin-net_id-netlink.h"

static void test_link_info_get(void) {
        log_debug("/* %s */", __func__);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_link_info_get();

        return 0;
}
