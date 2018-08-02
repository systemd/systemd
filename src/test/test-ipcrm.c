/* SPDX-License-Identifier: LGPL-2.1+ */

#include "clean-ipc.h"
#include "user-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        uid_t uid;
        int r;
        const char* name = argv[1] ?: NOBODY_USER_NAME;

        r = get_user_creds(&name, &uid, NULL, NULL, NULL, 0);
        if (r < 0) {
                log_full_errno(r == -ESRCH ? LOG_NOTICE : LOG_ERR,
                               r, "Failed to resolve \"%s\": %m", name);
                return r == -ESRCH ? EXIT_TEST_SKIP : EXIT_FAILURE;
        }

        r = clean_ipc_by_uid(uid);
        return  r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
