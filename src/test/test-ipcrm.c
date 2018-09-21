/* SPDX-License-Identifier: LGPL-2.1+ */

#include "clean-ipc.h"
#include "user-util.h"
#include "tests.h"
#include "util.h"

int main(int argc, char *argv[]) {
        uid_t uid;
        int r;
        const char* name = argv[1] ?: NOBODY_USER_NAME;

        test_setup_logging(LOG_INFO);

        r = get_user_creds(&name, &uid, NULL, NULL, NULL, 0);
        if (r == -ESRCH)
                return log_tests_skipped("Failed to resolve user");
        if (r < 0) {
                log_error_errno(r, "Failed to resolve \"%s\": %m", name);
                return EXIT_FAILURE;
        }

        r = clean_ipc_by_uid(uid);
        return  r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
