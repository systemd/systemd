/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "main-func.h"
#include "qrcode-util.h"
#include "tests.h"

static int run(int argc, char **argv) {
        const char *arg = argv[1] ?: "TEST";
        _cleanup_free_ char *header = NULL;
        int r;

        test_setup_logging(LOG_DEBUG);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_COLORS", "24bit", 1)); /* Force the qrcode to be printed */

        ASSERT_OK_POSITIVE(asprintf(&header, "This should say \"%s\"", arg));

        r = print_qrcode(stdout, header, arg);
        if (r == -EOPNOTSUPP)
                return log_tests_skipped("not supported");
        if (r < 0)
                return log_error_errno(r, "Failed to print QR code: %m");
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
