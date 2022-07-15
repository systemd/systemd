/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "locale-util.h"
#include "main-func.h"
#include "qrcode-util.h"
#include "tests.h"

static int run(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        assert_se(setenv("SYSTEMD_COLORS", "1", 1) == 0); /* Force the qrcode to be printed */

        r = print_qrcode(stdout, "This should say \"TEST\"", "TEST");
        if (r == -EOPNOTSUPP)
                return log_tests_skipped("not supported");
        if (r < 0)
                return log_error_errno(r, "Failed to print QR code: %m");
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
