/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cg_create) {
        int r;

        _cleanup_free_ char *here = NULL;
        ASSERT_OK(cg_pid_get_path_shifted(0, NULL, &here));

        /* cg_* will use path_simplify(), so use it here too otherwise when running in a container at the
         * root it asserts with "/test-b != //test-b" */
        _cleanup_free_ char *test_a = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-a"))),
                            *test_b = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b"))),
                            *test_c = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-c"))),
                            *test_d = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-d")));
        char *path;

        log_info("Paths for test:\n%s\n%s", test_a, test_b);

        /* Possibly clean up left-overs from aborted previous runs */
        (void) cg_trim(test_a, /* delete_root= */ true);
        (void) cg_trim(test_b, /* delete_root= */ true);

        r = cg_create(test_a);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r) || r == -ENOENT)
                return (void) log_tests_skipped_errno(r, "%s: Failed to create cgroup %s", __func__, test_a);

        ASSERT_OK_EQ(r, 1);
        ASSERT_OK_ZERO(cg_create(test_a));
        ASSERT_OK_EQ(cg_create(test_b), 1);
        ASSERT_OK_EQ(cg_create(test_c), 1);
        ASSERT_OK_ZERO(cg_create_and_attach(test_b, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_STREQ(path, test_b);
        free(path);

        ASSERT_OK_ZERO(cg_attach(test_a, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_a));
        free(path);

        ASSERT_OK_EQ(cg_create_and_attach(test_d, 0), 1);

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_d));
        free(path);

        ASSERT_OK_ZERO(cg_get_path(SYSTEMD_CGROUP_CONTROLLER, test_d, NULL, &path));
        log_debug("test_d: %s", path);
        ASSERT_TRUE(path_equal(path, strjoina("/sys/fs/cgroup", test_d)));
        free(path);

        ASSERT_OK_POSITIVE(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_a));
        ASSERT_OK_ZERO(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_b));
        ASSERT_OK_POSITIVE(cg_is_empty(NULL, test_a));
        ASSERT_OK_ZERO(cg_is_empty(NULL, test_b));

        ASSERT_OK_ZERO(cg_kill_recursive(test_a, 0, 0, NULL, NULL, NULL));
        ASSERT_OK_POSITIVE(cg_kill_recursive(test_b, 0, 0, NULL, NULL, NULL));

        ASSERT_OK(cg_trim(test_a, true));
        ASSERT_ERROR(cg_trim(test_b, true), EBUSY);

        ASSERT_OK_ZERO(cg_attach(here, 0));
        ASSERT_OK(cg_trim(test_b, true));
}

static int intro(void) {
        if (cg_is_ready() <= 0)
                return log_tests_skipped("cgroupfs is not mounted");

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
