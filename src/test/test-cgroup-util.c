/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "build.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "test-helper.h"
#include "tests.h"
#include "user-util.h"
#include "util.h"

static void check_p_d_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;
        int r;

        r = cg_path_decode_unit(path, &unit);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, result, code);
        assert_se(r == code);
        assert_se(streq_ptr(unit, result));
}

static void test_path_decode_unit(void) {
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
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, result, code);
        assert_se(r == code);
        assert_se(streq_ptr(unit, result));
}

static void test_path_get_unit(void) {
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

static void check_p_g_u_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;
        int r;

        r = cg_path_get_user_unit(path, &unit);
        printf("%s: %s → %s %d expected %s %d\n", __func__, path, unit, r, result, code);
        assert_se(r == code);
        assert_se(streq_ptr(unit, result));
}

static void test_path_get_user_unit(void) {
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
}

static void check_p_g_s(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_session(path, &s) == code);
        assert_se(streq_ptr(s, result));
}

static void test_path_get_session(void) {
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

static void test_path_get_owner_uid(void) {
        check_p_g_o_u("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, 1000);
        check_p_g_o_u("/user.slice/user-1006.slice", 0, 1006);
        check_p_g_o_u("", -ENXIO, 0);
}

static void check_p_g_slice(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_slice(path, &s) == code);
        assert_se(streq_ptr(s, result));
}

static void test_path_get_slice(void) {
        check_p_g_slice("/user.slice", 0, "user.slice");
        check_p_g_slice("/foobar", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("/user.slice/user-waldo.slice", 0, "user-waldo.slice");
        check_p_g_slice("", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("foobar", 0, SPECIAL_ROOT_SLICE);
        check_p_g_slice("foobar.slice", 0, "foobar.slice");
        check_p_g_slice("foo.slice/foo-bar.slice/waldo.service", 0, "foo-bar.slice");
}

static void check_p_g_u_slice(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_user_slice(path, &s) == code);
        assert_se(streq_ptr(s, result));
}

static void test_path_get_user_slice(void) {
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
}

static void test_get_paths(void) {
        _cleanup_free_ char *a = NULL;

        assert_se(cg_get_root_path(&a) >= 0);
        log_info("Root = %s", a);
}

static void test_proc(void) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        d = opendir("/proc");
        assert_se(d);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_free_ char *path = NULL, *path_shifted = NULL, *session = NULL, *unit = NULL, *user_unit = NULL, *machine = NULL, *slice = NULL;
                pid_t pid;
                uid_t uid = UID_INVALID;

                if (!IN_SET(de->d_type, DT_DIR, DT_UNKNOWN))
                        continue;

                r = parse_pid(de->d_name, &pid);
                if (r < 0)
                        continue;

                if (is_kernel_thread(pid))
                        continue;

                cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, pid, &path);
                cg_pid_get_path_shifted(pid, NULL, &path_shifted);
                cg_pid_get_owner_uid(pid, &uid);
                cg_pid_get_session(pid, &session);
                cg_pid_get_unit(pid, &unit);
                cg_pid_get_user_unit(pid, &user_unit);
                cg_pid_get_machine_name(pid, &machine);
                cg_pid_get_slice(pid, &slice);

                printf(PID_FMT"\t%s\t%s\t"UID_FMT"\t%s\t%s\t%s\t%s\t%s\n",
                       pid,
                       path,
                       path_shifted,
                       uid,
                       session,
                       unit,
                       user_unit,
                       machine,
                       slice);
        }
}

static void test_escape_one(const char *s, const char *r) {
        _cleanup_free_ char *b;

        b = cg_escape(s);
        assert_se(b);
        assert_se(streq(b, r));

        assert_se(streq(cg_unescape(b), s));
}

static void test_escape(void) {
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

static void test_controller_is_valid(void) {
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
        assert_se(streq_ptr(ret, path));
}

static void test_slice_to_path(void) {
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

        assert_se(cg_shift_path(raw, root, &s) >= 0);
        assert_se(streq(s, shifted));
}

static void test_shift_path(void) {

        test_shift_path_one("/foobar/waldo", "/", "/foobar/waldo");
        test_shift_path_one("/foobar/waldo", "", "/foobar/waldo");
        test_shift_path_one("/foobar/waldo", "/foobar", "/waldo");
        test_shift_path_one("/foobar/waldo", "/hogehoge", "/foobar/waldo");
}

static void test_mask_supported(void) {

        CGroupMask m;
        CGroupController c;

        assert_se(cg_mask_supported(&m) >= 0);

        for (c = 0; c < _CGROUP_CONTROLLER_MAX; c++)
                printf("'%s' is supported: %s\n", cgroup_controller_to_string(c), yes_no(m & CGROUP_CONTROLLER_TO_MASK(c)));
}

static void test_is_cgroup_fs(void) {
        struct statfs sfs;
        assert_se(statfs("/sys/fs/cgroup", &sfs) == 0);
        if (is_temporary_fs(&sfs))
                assert_se(statfs("/sys/fs/cgroup/systemd", &sfs) == 0);
        assert_se(is_cgroup_fs(&sfs));
}

static void test_fd_is_cgroup_fs(void) {
        int fd;

        fd = open("/sys/fs/cgroup", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        assert_se(fd >= 0);
        if (fd_is_temporary_fs(fd)) {
                fd = safe_close(fd);
                fd = open("/sys/fs/cgroup/systemd", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                assert_se(fd >= 0);
        }
        assert_se(fd_is_cgroup_fs(fd));
        fd = safe_close(fd);
}

static void test_is_wanted_print(bool header) {
        _cleanup_free_ char *cmdline = NULL;

        log_info("-- %s --", __func__);
        assert_se(proc_cmdline(&cmdline) >= 0);
        log_info("cmdline: %s", cmdline);
        if (header) {

                log_info(_CGROUP_HIERARCHY_);
                (void) system("findmnt -n /sys/fs/cgroup");
        }

        log_info("is_unified_wanted() → %s", yes_no(cg_is_unified_wanted()));
        log_info("is_hybrid_wanted() → %s", yes_no(cg_is_hybrid_wanted()));
        log_info("is_legacy_wanted() → %s", yes_no(cg_is_legacy_wanted()));
        log_info(" ");
}

static void test_is_wanted(void) {
        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0 "
                         "systemd.legacy_systemd_cgroup_controller", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "systemd.unified_cgroup_hierarchy=0 "
                         "systemd.legacy_systemd_cgroup_controller=0", 1) >= 0);
        test_is_wanted_print(false);

        /* cgroup_no_v1=all implies unified cgroup hierarchy, unless otherwise
         * explicitly specified. */
        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "cgroup_no_v1=all", 1) >= 0);
        test_is_wanted_print(false);

        assert_se(setenv("SYSTEMD_PROC_CMDLINE",
                         "cgroup_no_v1=all "
                         "systemd.unified_cgroup_hierarchy=0", 1) >= 0);
        test_is_wanted_print(false);
}

static void test_cg_tests(void) {
        int all, hybrid, systemd, r;

        r = cg_unified_flush();
        if (r == -ENOMEDIUM) {
                log_notice_errno(r, "Skipping cg hierarchy tests: %m");
                return;
        }
        assert_se(r == 0);

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

static void test_cg_get_keyed_attribute(void) {
        _cleanup_free_ char *val = NULL;
        char *vals3[3] = {}, *vals3a[3] = {};
        int i, r;

        r = cg_get_keyed_attribute("cpu", "/init.scope", "no_such_file", STRV_MAKE("no_such_attr"), &val);
        if (r == -ENOMEDIUM) {
                log_info_errno(r, "Skipping most of %s, /sys/fs/cgroup not accessible: %m", __func__);
                return;
        }

        assert_se(r == -ENOENT);
        assert_se(val == NULL);

        if (access("/sys/fs/cgroup/init.scope/cpu.stat", R_OK) < 0) {
                log_info_errno(errno, "Skipping most of %s, /init.scope/cpu.stat not accessible: %m", __func__);
                return;
        }

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("no_such_attr"), &val) == -ENXIO);
        assert_se(val == NULL);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("usage_usec"), &val) == 0);
        log_info("cpu /init.scope cpu.stat [usage_usec] → \"%s\"", val);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("usage_usec", "no_such_attr"), vals3) == -ENXIO);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat", STRV_MAKE("usage_usec", "usage_usec"), vals3) == -ENXIO);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat",
                                         STRV_MAKE("usage_usec", "user_usec", "system_usec"), vals3) == 0);
        log_info("cpu /init.scope cpu.stat [usage_usec user_usec system_usec] → \"%s\", \"%s\", \"%s\"",
                 vals3[0], vals3[1], vals3[2]);

        assert_se(cg_get_keyed_attribute("cpu", "/init.scope", "cpu.stat",
                                         STRV_MAKE("system_usec", "user_usec", "usage_usec"), vals3a) == 0);
        log_info("cpu /init.scope cpu.stat [system_usec user_usec usage_usec] → \"%s\", \"%s\", \"%s\"",
                 vals3a[0], vals3a[1], vals3a[2]);

        for (i = 0; i < 3; i++) {
                free(vals3[i]);
                free(vals3a[i]);
        }
}

int main(void) {
        test_setup_logging(LOG_DEBUG);

        test_path_decode_unit();
        test_path_get_unit();
        test_path_get_user_unit();
        test_path_get_session();
        test_path_get_owner_uid();
        test_path_get_slice();
        test_path_get_user_slice();
        TEST_REQ_RUNNING_SYSTEMD(test_get_paths());
        test_proc();
        TEST_REQ_RUNNING_SYSTEMD(test_escape());
        test_controller_is_valid();
        test_slice_to_path();
        test_shift_path();
        TEST_REQ_RUNNING_SYSTEMD(test_mask_supported());
        TEST_REQ_RUNNING_SYSTEMD(test_is_cgroup_fs());
        TEST_REQ_RUNNING_SYSTEMD(test_fd_is_cgroup_fs());
        test_is_wanted_print(true);
        test_is_wanted_print(false); /* run twice to test caching */
        test_is_wanted();
        test_cg_tests();
        test_cg_get_keyed_attribute();

        return 0;
}
