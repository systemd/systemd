/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"

static void check_p_d_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;
        int r;

        r = cg_path_decode_unit(path, &unit);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, strnull(result), code);
        assert_se(r == code);
        ASSERT_STREQ(unit, result);
}

TEST(path_decode_unit) {
        check_p_d_u("getty@tty2.service", 0, "getty@tty2.service");
        check_p_d_u("getty@tty2.service/", 0, "getty@tty2.service");
        check_p_d_u("getty@tty2.service/xxx", 0, "getty@tty2.service");
        check_p_d_u("getty@.service/", -ENXIO, NULL);
        check_p_d_u("getty@.service", -ENXIO, NULL);
        check_p_d_u("getty.service", 0, "getty.service");
        check_p_d_u("getty", -ENXIO, NULL);
        check_p_d_u("getty/waldo", -ENXIO, NULL);
        check_p_d_u("_cpu.service", 0, "cpu.service");
}

static void check_p_g_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;
        int r;

        r = cg_path_get_unit(path, &unit);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, strnull(result), code);
        assert_se(r == code);
        ASSERT_STREQ(unit, result);
}

TEST(path_get_unit) {
        check_p_g_u("/system.slice/foobar.service/sdfdsaf", 0, "foobar.service");
        check_p_g_u("/system.slice/getty@tty5.service", 0, "getty@tty5.service");
        check_p_g_u("/system.slice/getty@tty5.service/aaa/bbb", 0, "getty@tty5.service");
        check_p_g_u("/system.slice/getty@tty5.service/", 0, "getty@tty5.service");
        check_p_g_u("/system.slice/getty@tty6.service/tty5", 0, "getty@tty6.service");
        check_p_g_u("sadfdsafsda", -ENXIO, NULL);
        check_p_g_u("/system.slice/getty####@tty6.service/xxx", -ENXIO, NULL);
        check_p_g_u("/system.slice/system-waldo.slice/foobar.service/sdfdsaf", 0, "foobar.service");
        check_p_g_u("/system.slice/system-waldo.slice/_cpu.service/sdfdsaf", 0, "cpu.service");
        check_p_g_u("/user.slice/user-1000.slice/user@1000.service/server.service", 0, "user@1000.service");
        check_p_g_u("/user.slice/user-1000.slice/user@.service/server.service", -ENXIO, NULL);
}

static void check_p_g_u_f(const char *path, int expected_code, const char *expected_unit, const char *expected_subgroup) {
        _cleanup_free_ char *unit = NULL, *subgroup = NULL;
        int r;

        r = cg_path_get_unit_full(path, &unit, &subgroup);
        printf("%s: %s → %s %s %d expected %s %s %d\n", __func__, path, unit, subgroup, r, strnull(expected_unit), strnull(expected_subgroup), expected_code);
        ASSERT_EQ(r, expected_code);
        ASSERT_STREQ(unit, expected_unit);
        ASSERT_STREQ(subgroup, expected_subgroup);
}

TEST(path_get_unit_full) {
        check_p_g_u_f("/system.slice/foobar.service/sdfdsaf", 0, "foobar.service", "sdfdsaf");
        check_p_g_u_f("/system.slice/foobar.service//sdfdsaf", 0, "foobar.service", "sdfdsaf");
        check_p_g_u_f("/system.slice/foobar.service/sdfdsaf/", 0, "foobar.service", "sdfdsaf");
        check_p_g_u_f("/system.slice/foobar.service//sdfdsaf/", 0, "foobar.service", "sdfdsaf");
        check_p_g_u_f("/system.slice/foobar.service//sdfdsaf//", 0, "foobar.service", "sdfdsaf");
        check_p_g_u_f("/system.slice/foobar.service/sdfdsaf/urks", 0, "foobar.service", "sdfdsaf/urks");
        check_p_g_u_f("/system.slice/foobar.service//sdfdsaf//urks", 0, "foobar.service", "sdfdsaf/urks");
        check_p_g_u_f("/system.slice/foobar.service/sdfdsaf/urks/", 0, "foobar.service", "sdfdsaf/urks");
        check_p_g_u_f("/system.slice/foobar.service//sdfdsaf//urks//", 0, "foobar.service", "sdfdsaf/urks");
        check_p_g_u_f("/system.slice/foobar.service", 0, "foobar.service", NULL);
        check_p_g_u_f("/system.slice/foobar.service/", 0, "foobar.service", NULL);
        check_p_g_u_f("/system.slice/foobar.service//", 0, "foobar.service", NULL);
        check_p_g_u_f("/system.slice/", -ENXIO, NULL, NULL);
        check_p_g_u_f("/system.slice/piff", -ENXIO, NULL, NULL);
        check_p_g_u_f("/system.service/piff", 0, "system.service", "piff");
        check_p_g_u_f("//system.service//piff", 0, "system.service", "piff");
}

static void check_p_g_u_p(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit_path = NULL;
        int r;

        r = cg_path_get_unit_path(path, &unit_path);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit_path, r, strnull(result), code);
        assert_se(r == code);
        ASSERT_STREQ(unit_path, result);
}

TEST(path_get_unit_path) {
        check_p_g_u_p("/system.slice/foobar.service/sdfdsaf", 0, "/system.slice/foobar.service");
        check_p_g_u_p("/system.slice/getty@tty5.service", 0, "/system.slice/getty@tty5.service");
        check_p_g_u_p("/system.slice/getty@tty5.service/aaa/bbb", 0, "/system.slice/getty@tty5.service");
        check_p_g_u_p("/system.slice/getty@tty5.service/", 0, "/system.slice/getty@tty5.service");
        check_p_g_u_p("/system.slice/getty@tty6.service/tty5", 0, "/system.slice/getty@tty6.service");
        check_p_g_u_p("sadfdsafsda", -ENXIO, NULL);
        check_p_g_u_p("/system.slice/getty####@tty6.service/xxx", -ENXIO, NULL);
        check_p_g_u_p("/system.slice/system-waldo.slice/foobar.service/sdfdsaf", 0, "/system.slice/system-waldo.slice/foobar.service");
        check_p_g_u_p("/system.slice/system-waldo.slice/_cpu.service/sdfdsaf", 0, "/system.slice/system-waldo.slice/_cpu.service");
        check_p_g_u_p("/system.slice/system-waldo.slice/_cpu.service", 0, "/system.slice/system-waldo.slice/_cpu.service");
        check_p_g_u_p("/user.slice/user-1000.slice/user@1000.service/server.service", 0, "/user.slice/user-1000.slice/user@1000.service");
        check_p_g_u_p("/user.slice/user-1000.slice/user@.service/server.service", -ENXIO, NULL);
        check_p_g_u_p("/user.slice/_user-1000.slice/user@1000.service/foobar.slice/foobar@pie.service", 0, "/user.slice/_user-1000.slice/user@1000.service");
        check_p_g_u_p("/_session-2.scope/_foobar@pie.service/pa/po", 0, "/_session-2.scope");
}

static void check_p_g_u_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;
        int r;

        r = cg_path_get_user_unit(path, &unit);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, strnull(result), code);
        assert_se(r == code);
        ASSERT_STREQ(unit, result);
}

TEST(path_get_user_unit) {
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, "foobar.service");
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/waldo.slice/foobar.service", 0, "foobar.service");
        check_p_g_u_u("/user.slice/user-1002.slice/session-2.scope/foobar.service/waldo", 0, "foobar.service");
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/foobar.service/waldo/uuuux", 0, "foobar.service");
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/waldo/waldo/uuuux", -ENXIO, NULL);
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/session-2.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/xyz.slice/xyz-waldo.slice/session-77.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/meh.service", -ENXIO, NULL);
        check_p_g_u_u("/session-3.scope/_cpu.service", 0, "cpu.service");
        check_p_g_u_u("/user.slice/user-1000.slice/user@1000.service/server.service", 0, "server.service");
        check_p_g_u_u("/user.slice/user-1000.slice/user@1000.service/foobar.slice/foobar@pie.service", 0, "foobar@pie.service");
        check_p_g_u_u("/user.slice/user-1000.slice/user@.service/server.service", -ENXIO, NULL);
        check_p_g_u_u("/capsule.slice/capsule@test.service/app.slice/run-p9-i1.service", 0, "run-p9-i1.service");
        check_p_g_u_u("/capsule.slice/capsule@usr-joe.service/foo.slice/foo-bar.slice/run-p9-i1.service", 0, "run-p9-i1.service");
        check_p_g_u_u("/capsule.slice/capsule@#.service/foo.slice/foo-bar.slice/run-p9-i1.service", -ENXIO, NULL);
}

static void check_p_g_s(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_session(path, &s) == code);
        ASSERT_STREQ(s, result);
}

TEST(path_get_session) {
        check_p_g_s("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, "2");
        check_p_g_s("/session-3.scope", 0, "3");
        check_p_g_s("/session-.scope", -ENXIO, NULL);
        check_p_g_s("", -ENXIO, NULL);
}

static void check_p_g_o_u(const char *path, int code, uid_t result) {
        uid_t uid = 0;

        assert_se(cg_path_get_owner_uid(path, &uid) == code);
        assert_se(uid == result);
}

TEST(path_get_owner_uid) {
        check_p_g_o_u("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, 1000);
        check_p_g_o_u("/user.slice/user-1006.slice", 0, 1006);
        check_p_g_o_u("", -ENXIO, 0);
}

static void check_p_g_slice(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_slice(path, &s) == code);
        ASSERT_STREQ(s, result);
}

TEST(path_get_slice) {
        check_p_g_slice("/user.slice", 0, "user.slice");
        check_p_g_slice("/foobar", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("/user.slice/user-waldo.slice", 0, "user-waldo.slice");
        check_p_g_slice("", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("foobar", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("foobar.slice", 0, "foobar.slice");
        check_p_g_slice("foo.slice/foo-bar.slice/waldo.service", 0, "foo-bar.slice");
        check_p_g_slice("/capsule.slice/capsule@test.service/app.slice/run-p9-i1.service", 0, "capsule.slice");
}

static void check_p_g_u_slice(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_user_slice(path, &s) == code);
        ASSERT_STREQ(s, result);
}

TEST(path_get_user_slice) {
        check_p_g_u_slice("/user.slice", -ENXIO, NULL);
        check_p_g_u_slice("/foobar", -ENXIO, NULL);
        check_p_g_u_slice("/user.slice/user-waldo.slice", -ENXIO, NULL);
        check_p_g_u_slice("", -ENXIO, NULL);
        check_p_g_u_slice("foobar", -ENXIO, NULL);
        check_p_g_u_slice("foobar.slice", -ENXIO, NULL);
        check_p_g_u_slice("foo.slice/foo-bar.slice/waldo.service", -ENXIO, NULL);

        check_p_g_u_slice("foo.slice/foo-bar.slice/user@1000.service", 0, SPECIAL_ROOT_SLICE);
        check_p_g_u_slice("foo.slice/foo-bar.slice/user@1000.service/", 0, SPECIAL_ROOT_SLICE);
        check_p_g_u_slice("foo.slice/foo-bar.slice/user@1000.service///", 0, SPECIAL_ROOT_SLICE);
        check_p_g_u_slice("foo.slice/foo-bar.slice/user@1000.service/waldo.service", 0, SPECIAL_ROOT_SLICE);
        check_p_g_u_slice("foo.slice/foo-bar.slice/user@1000.service/piep.slice/foo.service", 0, "piep.slice");
        check_p_g_u_slice("/foo.slice//foo-bar.slice/user@1000.service/piep.slice//piep-pap.slice//foo.service", 0, "piep-pap.slice");

        check_p_g_u_slice("/capsule.slice/capsule@test.service/app.slice/run-p9-i1.service", 0, "app.slice");
        check_p_g_u_slice("/capsule.slice/capsule@usr-joe.service/app.slice/run-p9-i1.service", 0, "app.slice");
        check_p_g_u_slice("/capsule.slice/capsule@usr-joe.service/foo.slice/foo-bar.slice/run-p9-i1.service", 0, "foo-bar.slice");
}

TEST(get_paths, .sd_booted = true) {
        _cleanup_free_ char *a = NULL;

        assert_se(cg_get_root_path(&a) >= 0);
        log_info("Root = %s", a);
}

static inline bool hidden_cgroup(const char *p) {
        assert(p);

        /* Consider top-level cgroup hidden from us */
        return p[0] == '/' && p[strspn(p, "/")] == '.';
}

TEST(proc, .sd_booted = true) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        ASSERT_OK(proc_dir_open(&d));

        for (;;) {
                _cleanup_free_ char *path = NULL, *path_shifted = NULL, *session = NULL, *unit = NULL, *user_unit = NULL, *machine = NULL, *slice = NULL;
                _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
                uid_t uid = UID_INVALID;

                ASSERT_OK(r = proc_dir_read_pidref(d, &pid));
                if (r == 0)
                        break;

                if (pidref_is_kernel_thread(&pid) != 0)
                        continue;

                r = cg_pidref_get_path(&pid, &path);
                if (r == -ESRCH)
                        continue;
                ASSERT_OK(r);

                /* Test may run in a container with supervising/monitor processes that don't belong to our
                 * cgroup tree (slices/leaves) */
                if (hidden_cgroup(path))
                        continue;

                int r1 = cg_pid_get_path_shifted(pid.pid, NULL, &path_shifted);
                int r2 = cg_pidref_get_unit(&pid, &unit);
                int r3 = cg_pid_get_slice(pid.pid, &slice);

                /* Not all processes belong to a specific user or a machine */
                int r4 = cg_pidref_get_owner_uid(&pid, &uid);
                int r5 = cg_pidref_get_session(&pid, &session);
                int r6 = cg_pid_get_user_unit(pid.pid, &user_unit);
                int r7 = cg_pid_get_machine_name(pid.pid, &machine);

                log_debug(PID_FMT": %s, %s, "UID_FMT", %s, %s, %s, %s, %s",
                          pid.pid,
                          path,
                          strna(path_shifted),
                          uid,
                          strna(session),
                          strna(unit),
                          strna(user_unit),
                          strna(machine),
                          strna(slice));

                ASSERT_OK_OR(r1, -ESRCH);
                ASSERT_OK_OR(r2, -ESRCH, -ENXIO);
                ASSERT_OK_OR(r3, -ESRCH, -ENXIO);
                ASSERT_OK_OR(r4, -ESRCH, -ENXIO);
                ASSERT_OK_OR(r5, -ESRCH, -ENXIO);
                ASSERT_OK_OR(r6, -ESRCH, -ENXIO);
                ASSERT_OK_OR(r7, -ESRCH, -ENXIO, -ENOENT);
        }
}

static void test_escape_one(const char *s, const char *expected) {
        _cleanup_free_ char *b = NULL;

        assert_se(s);
        assert_se(expected);

        ASSERT_OK(cg_escape(s, &b));
        ASSERT_STREQ(b, expected);

        ASSERT_STREQ(cg_unescape(b), s);

        assert_se(filename_is_valid(b));
        assert_se(!cg_needs_escape(s) || b[0] == '_');
}

TEST(escape, .sd_booted = true) {
        test_escape_one("foobar", "foobar");
        test_escape_one(".foobar", "_.foobar");
        test_escape_one("foobar.service", "foobar.service");
        test_escape_one("cgroup.service", "_cgroup.service");
        test_escape_one("tasks", "_tasks");
        if (access("/sys/fs/cgroup/cpu", F_OK) == 0)
                test_escape_one("cpu.service", "_cpu.service");
        test_escape_one("_foobar", "__foobar");
        test_escape_one("", "_");
        test_escape_one("_", "__");
        test_escape_one(".", "_.");
}

static void test_slice_to_path_one(const char *unit, const char *path, int error) {
        _cleanup_free_ char *ret = NULL;
        int r;

        log_info("unit: %s", unit);

        r = cg_slice_to_path(unit, &ret);
        log_info("actual: %s / %d", strnull(ret), r);
        log_info("expect: %s / %d", strnull(path), error);
        assert_se(r == error);
        ASSERT_STREQ(ret, path);
}

TEST(slice_to_path) {
        test_slice_to_path_one("foobar.slice", "foobar.slice", 0);
        test_slice_to_path_one("foobar-waldo.slice", "foobar.slice/foobar-waldo.slice", 0);
        test_slice_to_path_one("foobar-waldo.service", NULL, -EINVAL);
        test_slice_to_path_one(SPECIAL_ROOT_SLICE, "", 0);
        test_slice_to_path_one("--.slice", NULL, -EINVAL);
        test_slice_to_path_one("-", NULL, -EINVAL);
        test_slice_to_path_one("-foo-.slice", NULL, -EINVAL);
        test_slice_to_path_one("-foo.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo-.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo--bar.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo.slice/foo--bar.slice", NULL, -EINVAL);
        test_slice_to_path_one("a-b.slice", "a.slice/a-b.slice", 0);
        test_slice_to_path_one("a-b-c-d-e.slice", "a.slice/a-b.slice/a-b-c.slice/a-b-c-d.slice/a-b-c-d-e.slice", 0);

        test_slice_to_path_one("foobar@.slice", NULL, -EINVAL);
        test_slice_to_path_one("foobar@waldo.slice", NULL, -EINVAL);
        test_slice_to_path_one("foobar@waldo.service", NULL, -EINVAL);
        test_slice_to_path_one("-foo@-.slice", NULL, -EINVAL);
        test_slice_to_path_one("-foo@.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo@-.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo@@bar.slice", NULL, -EINVAL);
        test_slice_to_path_one("foo.slice/foo@@bar.slice", NULL, -EINVAL);
}

static void test_shift_path_one(const char *raw, const char *root, const char *shifted) {
        const char *s = NULL;

        ASSERT_OK(cg_shift_path(raw, root, &s));
        ASSERT_STREQ(s, shifted);
}

TEST(shift_path) {
        test_shift_path_one("/foobar/waldo", "/", "/foobar/waldo");
        test_shift_path_one("/foobar/waldo", "", "/foobar/waldo");
        test_shift_path_one("/foobar/waldo", "/foobar", "/waldo");
        test_shift_path_one("/foobar/waldo", "/hogehoge", "/foobar/waldo");
}

TEST(mask_supported, .sd_booted = true) {
        CGroupMask m;

        ASSERT_OK(cg_mask_supported(&m));

        for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++)
                printf("'%s' is supported: %s\n",
                       cgroup_controller_to_string(c),
                       yes_no(m & CGROUP_CONTROLLER_TO_MASK(c)));
}

TEST(cg_get_keyed_attribute) {
        _cleanup_free_ char *val = NULL;
        char *vals3[3] = {}, *vals3a[3] = {};
        int r;

        if (cg_is_ready() <= 0)
                return (void) log_tests_skipped("/sys/fs/cgroup/ not available");

        r = cg_get_keyed_attribute("/init.scope", "no_such_file", STRV_MAKE("no_such_attr"), &val);
        if (ERRNO_IS_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "/sys/fs/cgroup not accessible");

        assert_se(r == -ENOENT);
        ASSERT_NULL(val);

        if (access("/sys/fs/cgroup/init.scope/cpu.stat", R_OK) < 0)
                return (void) log_tests_skipped_errno(errno, "/init.scope/cpu.stat not accessible");

        assert_se(cg_get_keyed_attribute("/init.scope", "cpu.stat", STRV_MAKE("no_such_attr"), &val) == -ENXIO);
        ASSERT_NULL(val);

        assert_se(cg_get_keyed_attribute("/init.scope", "cpu.stat", STRV_MAKE("usage_usec"), &val) == 0);
        val = mfree(val);

        assert_se(cg_get_keyed_attribute("/init.scope", "cpu.stat", STRV_MAKE("usage_usec", "no_such_attr"), vals3) == -ENXIO);

        assert_se(cg_get_keyed_attribute("/init.scope", "cpu.stat",
                                         STRV_MAKE("usage_usec", "user_usec", "system_usec"), vals3) == 0);
        for (size_t i = 0; i < 3; i++)
                free(vals3[i]);

        assert_se(cg_get_keyed_attribute("/init.scope", "cpu.stat",
                                         STRV_MAKE("system_usec", "user_usec", "usage_usec"), vals3a) == 0);
        for (size_t i = 0; i < 3; i++)
                free(vals3a[i]);
}

TEST(bfq_weight_conversion) {
        assert_se(BFQ_WEIGHT(1) == 1);
        assert_se(BFQ_WEIGHT(50) == 50);
        assert_se(BFQ_WEIGHT(100) == 100);
        assert_se(BFQ_WEIGHT(500) == 136);
        assert_se(BFQ_WEIGHT(5000) == 545);
        assert_se(BFQ_WEIGHT(10000) == 1000);
}

TEST(cgroupid) {
        _cleanup_free_ char *p = NULL, *p2 = NULL;
        _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
        uint64_t id, id2;

        if (cg_is_ready() <= 0)
                return (void) log_tests_skipped("cgroupfs is not mounted");

        fd = cg_path_open("/");
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
