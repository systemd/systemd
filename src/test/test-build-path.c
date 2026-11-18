/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "build-path.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

TEST(build_exec_dir) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = get_build_exec_dir(&p);
        if (r == -ENOEXEC)
                log_info("Not run from build dir.");
        else if (r < 0)
                log_error_errno(r, "Failed to find build dir: %m");
        else
                log_info("%s", strna(p));
}

DEFINE_TEST_MAIN(LOG_INFO);
