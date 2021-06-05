/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

static void test_cg_split_spec(void) {
        char *c, *p;

        log_info("/* %s */", __func__);

        assert_se(cg_split_spec("foobar:/", &c, &p) == 0);
        assert_se(streq(c, "foobar"));
        assert_se(streq(p, "/"));
        c = mfree(c);
        p = mfree(p);

        assert_se(cg_split_spec("foobar:", &c, &p) == 0);
        c = mfree(c);
        p = mfree(p);

        assert_se(cg_split_spec("foobar:asdfd", &c, &p) < 0);
        assert_se(cg_split_spec(":///", &c, &p) < 0);
        assert_se(cg_split_spec(":", &c, &p) < 0);
        assert_se(cg_split_spec("", &c, &p) < 0);
        assert_se(cg_split_spec("fo/obar:/", &c, &p) < 0);

        assert_se(cg_split_spec("/", &c, &p) >= 0);
        assert_se(c == NULL);
        assert_se(streq(p, "/"));
        p = mfree(p);

        assert_se(cg_split_spec("foo", &c, &p) >= 0);
        assert_se(streq(c, "foo"));
        assert_se(p == NULL);
        c = mfree(c);
}

static void test_cg_create(void) {
        log_info("/* %s */", __func__);
        int r;

        r = cg_unified_cached(false);
        if (r == -ENOMEDIUM) {
                log_tests_skipped("cgroup not mounted");
                return;
        }
        assert_se(r >= 0);

        _cleanup_free_ char *here = NULL;
        assert_se(cg_pid_get_path_shifted(0, NULL, &here) >= 0);

        const char *test_a = prefix_roota(here, "/test-a"),
                   *test_b = prefix_roota(here, "/test-b"),
                   *test_c = prefix_roota(here, "/test-b/test-c"),
                   *test_d = prefix_roota(here, "/test-b/test-d");
        char *path;

        log_info("Paths for test:\n%s\n%s", test_a, test_b);

        r = cg_create(SYSTEMD_CGROUP_CONTROLLER, test_a);
        if (IN_SET(r, -EPERM, -EACCES, -EROFS)) {
                log_info_errno(r, "Skipping %s: %m", __func__);
                return;
        }

        assert_se(r == 1);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_a) == 0);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_b) == 1);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, test_c) == 1);
        assert_se(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, test_b, 0) == 0);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path) == 0);
        assert_se(streq(path, test_b));
        free(path);

        assert_se(cg_attach(SYSTEMD_CGROUP_CONTROLLER, test_a, 0) == 0);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path) == 0);
        assert_se(path_equal(path, test_a));
        free(path);

        assert_se(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, test_d, 0) == 1);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid_cached(), &path) == 0);
        assert_se(path_equal(path, test_d));
        free(path);

        assert_se(cg_get_path(SYSTEMD_CGROUP_CONTROLLER, test_d, NULL, &path) == 0);
        log_debug("test_d: %s", path);
        const char *full_d;
        if (cg_all_unified())
                full_d = strjoina("/sys/fs/cgroup", test_d);
        else if (cg_hybrid_unified())
                full_d = strjoina("/sys/fs/cgroup/unified", test_d);
        else
                full_d = strjoina("/sys/fs/cgroup/systemd", test_d);
        assert_se(path_equal(path, full_d));
        free(path);

        assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_a) > 0);
        assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, test_b) > 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a) > 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b) == 0);

        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a, 0, 0, NULL, NULL, NULL) == 0);
        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b, 0, 0, NULL, NULL, NULL) > 0);

        assert_se(cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b, SYSTEMD_CGROUP_CONTROLLER, test_a, 0) > 0);

        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a) == 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b) > 0);

        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a, 0, 0, NULL, NULL, NULL) > 0);
        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, test_b, 0, 0, NULL, NULL, NULL) == 0);

        cg_trim(SYSTEMD_CGROUP_CONTROLLER, test_b, false);

        assert_se(cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, test_b) == 0);
        assert_se(cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, test_a) < 0);
        assert_se(cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, test_a, SYSTEMD_CGROUP_CONTROLLER, here, 0) > 0);
        assert_se(cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, test_a) == 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_cg_split_spec();
        test_cg_create();

        return 0;
}
