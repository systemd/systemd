/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze-verify-util.h"
#include "tests.h"

static void test_verify_nonexistent(void) {
        /* Negative cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/non/existent"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/non/existent"}, NULL) < 0);

        /* Ordinary cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/bin/echo"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/bin/echo"}, NULL) == 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_verify_nonexistent();
}
