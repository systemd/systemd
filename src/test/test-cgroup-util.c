/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "special.h"
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
        assert_se(r == expected_code);
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

                r = cg_pidref_get_path(SYSTEMD_CGROUP_CONTROLLER, &pid, &path);
                if (r == -ESRCH)
                        continue;
                ASSERT_OK(r);

                /* Test may run in a container with supervising/monitor processes that don't belong to our
                 * cgroup tree (slices/leaves) */
                if (hidden_cgroup(path))
                        continue;

                r = cg_pid_get_path_shifted(pid.pid, NULL, &path_shifted);
                if (r != -ESRCH)
                        ASSERT_OK(r);
                r = cg_pidref_get_unit(&pid, &unit);
                if (r != -ESRCH)
                        ASSERT_OK(r);
                r = cg_pid_get_slice(pid.pid, &slice);
                if (r != -ESRCH)
                        ASSERT_OK(r);

                /* Not all processes belong to a specific user or a machine */
                r = cg_pidref_get_owner_uid(&pid, &uid);
                if (!IN_SET(r, -ESRCH, -ENXIO))
                        ASSERT_OK(r);
                r = cg_pidref_get_session(&pid, &session);
                if (!IN_SET(r, -ESRCH, -ENXIO))
                        ASSERT_OK(r);
                r = cg_pid_get_user_unit(pid.pid, &user_unit);
                if (!IN_SET(r, -ESRCH, -ENXIO))
                        ASSERT_OK(r);
                r = cg_pid_get_machine_name(pid.pid, &machine);
                if (!IN_SET(r, -ESRCH, -ENOENT))
                        ASSERT_OK(r);

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

TEST(controller_is_valid) {
        assert_se(cg_controller_is_valid("foobar"));
        assert_se(cg_controller_is_valid("foo_bar"));
        assert_se(cg_controller_is_valid("name=foo"));
        assert_se(!cg_controller_is_valid(""));
        assert_se(!cg_controller_is_valid("name="));
        assert_se(!cg_controller_is_valid("="));
        assert_se(!cg_controller_is_valid("cpu,cpuacct"));
        assert_se(!cg_controller_is_valid("_"));
        assert_se(!cg_controller_is_valid("_foobar"));
        assert_se(!cg_controller_is_valid("tatü"));
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

TEST(cg_tests) {
        int all, hybrid, systemd, r;

        r = cg_unified();
        if (IN_SET(r, -ENOENT, -ENOMEDIUM)) {
                log_tests_skipped("cgroup not mounted");
                return;
        }
        assert_se(r >= 0);

        all = cg_all_unified();
        assert_se(IN_SET(all, 0, 1));

        hybrid = cg_hybrid_unified();
        assert_se(IN_SET(hybrid, 0, 1));

        systemd = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        assert_se(IN_SET(systemd, 0, 1));

        if (all) {
                assert_se(systemd);
                assert_se(!hybrid);

        } else if (hybrid) {
                assert_se(systemd);
                assert_se(!all);

        } else
                assert_se(!systemd);
}

TEST(cg_get_keyed_attribute) {
        _cleanup_free_ char *val = NULL;
        char *vals3[3] = {}, *vals3a[3] = {};
        int r;

        r = cg_get_keyed_attribute("cpu", "/init.scope", "no_such_file", STRV_MAKE("no_such_attr"), &val);
        if (IN_SET(r, -ENOMEDIUM, -ENOENT) || ERRNO_IS_PRIVILEGE(r)) {
                log_info_errno(r, "Skipping most of %s, /sys/fs/cgroup not accessible: %m", __func__);
                return;
        }

        assert_se(r == -ENOENT);
        ASSERT_NULL(val);

        if (access("/sys/fs/cgroup/init.scope/cpu.stat", R_OK) < 0) {
                log_info_errno(errno, "Skipping most of %s, /init.scope/cpu.stat not accessible: %m", __func__);
                return;
        }

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("no_such_attr"), &val) == -ENXIO);
        ASSERT_NULL(val);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("usage_usec"), &val) == 0);
        val = mfree(val);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("usage_usec", "no_such_attr"), vals3) == -ENXIO);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat",
                                         STRV_MAKE("usage_usec", "user_usec", "system_usec"), vals3) == 0);
        for (size_t i = 0; i < 3; i++)
                free(vals3[i]);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat",
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

DEFINE_TEST_MAIN(LOG_DEBUG);
