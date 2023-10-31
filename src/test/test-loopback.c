/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <stdio.h>
#include <string.h>

#include "errno-util.h"
#include "log.h"
#include "loopback-setup.h"
#include "tests.h"

TEST_RET(loopback_setup) {
        int r;

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                if (ERRNO_IS_PRIVILEGE(errno) || ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_tests_skipped("lacking privileges or namespaces not supported");
                return log_error_errno(errno, "Failed to create user+network namespace: %m");
        }

        r = loopback_setup();
        if (r < 0)
                return log_error_errno(r, "loopback: %m");

        log_info("> ipv6 main");
        /* <0 → fork error, ==0 → success, >0 → error in child */
        assert_se(system("ip -6 route show table main") >= 0);

        log_info("> ipv6 local");
        assert_se(system("ip -6 route show table local") >=0);

        log_info("> ipv4 main");
        assert_se(system("ip -4 route show table main") >= 0);

        log_info("> ipv4 local");
        assert_se(system("ip -4 route show table local") >= 0);

        return EXIT_SUCCESS;
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
