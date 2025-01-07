/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "process-util.h"
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
        if (IN_SET(r, -ENOMEDIUM, -ENOENT)) {
                log_tests_skipped("cgroupfs is not mounted");
                return;
        }
        ASSERT_OK(r);

        _cleanup_free_ char *here = NULL;
        ASSERT_OK(cg_pid_get_path_shifted(0, NULL, &here));

        const char *test_a = prefix_roota(here, "/test-a"),
                   *test_b = prefix_roota(here, "/test-b"),
                   *test_c = prefix_roota(here, "/test-b/test-c"),
                   *test_d = prefix_roota(here, "/test-b/test-d");
        char *path;

        log_info("Paths for test:\n%s\n%s", test_a, test_b);

        /* Possibly clean up left-overs from aboted previous runs */
        (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER, test_a, /* delete_root= */ true);
        (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER, test_b, /* delete_root= */ true);

        r = cg_create(SYSTEMD_CGROUP_CONTROLLER, test_a);
        if (IN_SET(r, -EPERM, -EACCES, -EROFS)) {
                log_info_errno(r, "Skipping %s: %m", __func__);
                return;
        }

        ASSERT_OK_EQ(r, 1);
        ASSERT_OK_ZERO(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_a));
        ASSERT_OK_EQ(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_b), 1);
        ASSERT_OK_EQ(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_c), 1);
        ASSERT_OK_ZERO(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, test_b, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path));
        ASSERT_STREQ(path, test_b);
        free(path);

        ASSERT_OK_ZERO(cg_attach(SYSTEMD_CGROUP_CONTROLLER, test_a, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_a));
        free(path);

        ASSERT_OK_EQ(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, test_d, 0), 1);

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
        ASSERT_OK_POSITIVE(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_b));
        ASSERT_OK_POSITIVE(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a));
        ASSERT_OK_ZERO(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b));

        ASSERT_OK_ZERO(cg_kill_recursive(test_a, 0, 0, NULL, NULL, NULL));
        ASSERT_OK_POSITIVE(cg_kill_recursive(test_b, 0, 0, NULL, NULL, NULL));

        ASSERT_OK_POSITIVE(cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b, SYSTEMD_CGROUP_CONTROLLER, test_a, 0));

        ASSERT_OK_ZERO(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a));
        ASSERT_OK_POSITIVE(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b));

        ASSERT_OK_POSITIVE(cg_kill_recursive(test_a, 0, 0, NULL, NULL, NULL));
        ASSERT_OK_ZERO(cg_kill_recursive(test_b, 0, 0, NULL, NULL, NULL));

        ASSERT_OK(cg_trim(SYSTEMD_CGROUP_CONTROLLER, test_b, true));
}

TEST(id) {
        _cleanup_free_ char *p = NULL, *p2 = NULL;
        _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
        uint64_t id, id2;
        int r;

        r = cg_all_unified();
        if (r == 0) {
                log_tests_skipped("skipping cgroupid test, not running in unified mode");
                return;
        }
        if (IN_SET(r, -ENOMEDIUM, -ENOENT)) {
                log_tests_skipped("cgroupfs is not mounted");
                return;
        }
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
