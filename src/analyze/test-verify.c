/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "analyze.h"
#include "analyze-verify-util.h"
#include "execute.h"
#include "fileio.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

const char *arg_instance = "test_instance";

TEST(verify_nonexistent) {
        /* Negative cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/non/existent"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/non/existent"}, NULL) < 0);

        /* Ordinary cases */
        assert_se(verify_executable(NULL, &(ExecCommand) {.path = (char*) "/bin/echo"}, NULL) == 0);
        assert_se(verify_executable(NULL, &(ExecCommand) {.flags = EXEC_COMMAND_IGNORE_FAILURE, .path = (char*) "/bin/echo"}, NULL) == 0);
}

static void test_verify_set_unit_path_one(const char *old, const char *expected) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *unit = NULL;
        char *unit_paths[2];

        ASSERT_OK(mkdtemp_malloc("/tmp/test-verify.XXXXXX", &tmp));
        unit = ASSERT_NOT_NULL(path_join(tmp, "test.service"));
        ASSERT_OK(write_string_file(unit, "[Unit]\nDescription=test\n", WRITE_STRING_FILE_CREATE));

        if (old)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));

        unit_paths[0] = unit;
        unit_paths[1] = NULL;

        if (expected) {
                ASSERT_OK(verify_set_unit_path(unit_paths));
                ASSERT_STREQ(getenv("SYSTEMD_UNIT_PATH"), strjoina(tmp, expected));
        } else
                ASSERT_ERROR(verify_set_unit_path(unit_paths), EINVAL);
}

TEST(verify_set_unit_path) {
        _cleanup_free_ char *old_saved = getenv("SYSTEMD_UNIT_PATH") ? strdup(getenv("SYSTEMD_UNIT_PATH")) : NULL;
        ASSERT_TRUE(old_saved || !getenv("SYSTEMD_UNIT_PATH"));

        test_verify_set_unit_path_one(NULL, ":");
        test_verify_set_unit_path_one("", "");
        test_verify_set_unit_path_one(":", ":");
        test_verify_set_unit_path_one("/foo:", ":/foo:");
        test_verify_set_unit_path_one(":foo", NULL);
        test_verify_set_unit_path_one("/foo::/bar", NULL);

        if (old_saved)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_UNIT_PATH", old_saved, 1));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_UNIT_PATH"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
