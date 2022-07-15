/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "loopback-setup.h"
#include "tests.h"

int main(int argc, char* argv[]) {
        int r;

        test_setup_logging(LOG_DEBUG);

        r = loopback_setup();
        if (r < 0)
                log_error_errno(r, "loopback: %m");

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
