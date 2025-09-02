/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cg_split_spec) {
        char *c, *p;

        ASSERT_OK_ZERO(cg_split_spec("foobar:/", &c, &p));
        ASSERT_STREQ(c, "foobar");
        ASSERT_STREQ(p, "/");
        c = mfree(c);
        p = mfree(p);

        ASSERT_OK_ZERO(cg_split_spec("foobar:", &c, &p));
        c = mfree(c);
        p = mfree(p);

        ASSERT_FAIL(cg_split_spec("foobar:asdfd", &c, &p));
        ASSERT_FAIL(cg_split_spec(":///", &c, &p));
        ASSERT_FAIL(cg_split_spec(":", &c, &p));
        ASSERT_FAIL(cg_split_spec("", &c, &p));
        ASSERT_FAIL(cg_split_spec("fo/obar:/", &c, &p));

        ASSERT_OK(cg_split_spec("/", &c, &p));
        ASSERT_NULL(c);
        ASSERT_STREQ(p, "/");
        p = mfree(p);

        ASSERT_OK(cg_split_spec("foo", &c, &p));
        ASSERT_STREQ(c, "foo");
        ASSERT_NULL(p);
        c = mfree(c);
}

TEST(cg_create) {
        int r;

        r = cg_unified_cached(false);
        if (IN_SET(r, -ENOMEDIUM, -ENOENT))
                return (void) log_tests_skipped("cgroupfs is not mounted");
        ASSERT_OK(r);

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

        ASSERT_OK_ZERO(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path));
        ASSERT_STREQ(path, test_b);
        free(path);

        ASSERT_OK_ZERO(cg_attach(test_a, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_a));
        free(path);

        ASSERT_OK_EQ(cg_create_and_attach(test_d, 0), 1);

        ASSERT_OK_ZERO(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_d));
        free(path);

        ASSERT_OK_ZERO(cg_get_path(SYSTEMD_CGROUP_CONTROLLER, test_d, NULL, &path));
        log_debug("test_d: %s", path);
        const char *full_d;
        if (cg_all_unified())
                full_d = strjoina("/sys/fs/cgroup", test_d);
        else if (cg_hybrid_unified())
                full_d = strjoina("/sys/fs/cgroup/unified", test_d);
        else
                full_d = strjoina("/sys/fs/cgroup/systemd", test_d);
        ASSERT_TRUE(path_equal(path, full_d));
        free(path);

        ASSERT_OK_POSITIVE(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_a));
        ASSERT_OK_ZERO(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_b));
        ASSERT_OK_POSITIVE(cg_is_empty(NULL, test_a));
        ASSERT_OK_POSITIVE(cg_is_empty(NULL, test_b));

        ASSERT_OK_ZERO(cg_kill_recursive(test_a, 0, 0, NULL, NULL, NULL));
        ASSERT_OK_POSITIVE(cg_kill_recursive(test_b, 0, 0, NULL, NULL, NULL));

        ASSERT_OK(cg_trim(test_a, true));
        ASSERT_ERROR(cg_trim(test_b, true), EBUSY);

        ASSERT_OK_ZERO(cg_attach(here, 0));
        ASSERT_OK(cg_trim(test_b, true));
}

TEST(id) {
        _cleanup_free_ char *p = NULL, *p2 = NULL;
        _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
        uint64_t id, id2;
        int r;

        r = cg_all_unified();
        if (IN_SET(r, -ENOMEDIUM, -ENOENT))
                return (void) log_tests_skipped("cgroupfs is not mounted");
        if (r == 0)
                return (void) log_tests_skipped("skipping cgroupid test, not running in unified mode");
        ASSERT_OK_POSITIVE(r);

        fd = cg_path_open(SYSTEMD_CGROUP_CONTROLLER, "/");
        ASSERT_OK(fd);

        ASSERT_OK(fd_get_path(fd, &p));
        ASSERT_TRUE(path_equal(p, "/sys/fs/cgroup"));

        ASSERT_OK(cg_fd_get_cgroupid(fd, &id));

        fd2 = cg_cgroupid_open(fd, id);

        if (ERRNO_IS_NEG_PRIVILEGE(fd2))
                log_notice("Skipping open-by-cgroup-id test because lacking privs.");
        else if (ERRNO_IS_NEG_NOT_SUPPORTED(fd2))
                log_notice("Skipping open-by-cgroup-id test because syscall is missing or blocked.");
        else {
                ASSERT_OK(fd2);

                ASSERT_OK(fd_get_path(fd2, &p2));
                ASSERT_TRUE(path_equal(p2, "/sys/fs/cgroup"));

                ASSERT_OK(cg_fd_get_cgroupid(fd2, &id2));

                ASSERT_EQ(id, id2);

                ASSERT_OK_EQ(inode_same_at(fd, NULL, fd2, NULL, AT_EMPTY_PATH), true);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
