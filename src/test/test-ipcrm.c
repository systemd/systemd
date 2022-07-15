/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "clean-ipc.h"
#include "errno-util.h"
#include "main-func.h"
#include "tests.h"
#include "user-util.h"

static int run(int argc, char *argv[]) {
        uid_t uid;
        int r;
        const char* name = argv[1] ?: NOBODY_USER_NAME;

        test_setup_logging(LOG_INFO);

        r = get_user_creds(&name, &uid, NULL, NULL, NULL, 0);
        if (r == -ESRCH)
                return log_tests_skipped("Failed to resolve user");
        if (r < 0)
                return log_error_errno(r, "Failed to resolve \"%s\": %m", name);

        r = clean_ipc_by_uid(uid);
        if (ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("No privileges");

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
