/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>

#include "util.h"
#include "cgroup-util.h"
#include "test-helper.h"

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
        check_p_d_u("getty@.service/", -EINVAL, NULL);
        check_p_d_u("getty@.service", -EINVAL, NULL);
        check_p_d_u("getty.service", 0, "getty.service");
        check_p_d_u("getty", -EINVAL, NULL);
        check_p_d_u("getty/waldo", -EINVAL, NULL);
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
        check_p_g_u("sadfdsafsda", -EINVAL, NULL);
        check_p_g_u("/system.slice/getty####@tty6.service/xxx", -EINVAL, NULL);
        check_p_g_u("/system.slice/system-waldo.slice/foobar.service/sdfdsaf", 0, "foobar.service");
        check_p_g_u("/system.slice/system-waldo.slice/_cpu.service/sdfdsaf", 0, "cpu.service");
        check_p_g_u("/user.slice/user-1000.slice/user@1000.service/server.service", 0, "user@1000.service");
        check_p_g_u("/user.slice/user-1000.slice/user@.service/server.service", -EINVAL, NULL);
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
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/waldo/waldo/uuuux", -EINVAL, NULL);
        check_p_g_u_u("/user.slice/user-1000.slice/session-2.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/session-2.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/xyz.slice/xyz-waldo.slice/session-77.scope/foobar@pie.service/pa/po", 0, "foobar@pie.service");
        check_p_g_u_u("/meh.service", -ENOENT, NULL);
        check_p_g_u_u("/session-3.scope/_cpu.service", 0, "cpu.service");
        check_p_g_u_u("/user.slice/user-1000.slice/user@1000.service/server.service", 0, "server.service");
        check_p_g_u_u("/user.slice/user-1000.slice/user@.service/server.service", -ENOENT, NULL);
}

static void check_p_g_s(const char *path, int code, const char *result) {
        _cleanup_free_ char *s = NULL;

        assert_se(cg_path_get_session(path, &s) == code);
        assert_se(streq_ptr(s, result));
}

static void test_path_get_session(void) {
        check_p_g_s("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, "2");
        check_p_g_s("/session-3.scope", 0, "3");
        check_p_g_s("", -ENOENT, 0);
}

static void check_p_g_o_u(const char *path, int code, uid_t result) {
        uid_t uid = 0;

        assert_se(cg_path_get_owner_uid(path, &uid) == code);
        assert_se(uid == result);
}

static void test_path_get_owner_uid(void) {
        check_p_g_o_u("/user.slice/user-1000.slice/session-2.scope/foobar.service", 0, 1000);
        check_p_g_o_u("/user.slice/user-1006.slice", 0, 1006);
        check_p_g_o_u("", -ENOENT, 0);
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
                uid_t uid = (uid_t) -1;

                if (de->d_type != DT_DIR &&
                    de->d_type != DT_UNKNOWN)
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
        assert_se(cg_controller_is_valid("foobar", false));
        assert_se(cg_controller_is_valid("foo_bar", false));
        assert_se(cg_controller_is_valid("name=foo", true));
        assert_se(!cg_controller_is_valid("", false));
        assert_se(!cg_controller_is_valid("name=", true));
        assert_se(!cg_controller_is_valid("=", false));
        assert_se(!cg_controller_is_valid("cpu,cpuacct", false));
        assert_se(!cg_controller_is_valid("_", false));
        assert_se(!cg_controller_is_valid("_foobar", false));
        assert_se(!cg_controller_is_valid("tatü", false));
}

static void test_slice_to_path_one(const char *unit, const char *path, int error) {
        _cleanup_free_ char *ret = NULL;

        assert_se(cg_slice_to_path(unit, &ret) == error);
        assert_se(streq_ptr(ret, path));
}

static void test_slice_to_path(void) {

        test_slice_to_path_one("foobar.slice", "foobar.slice", 0);
        test_slice_to_path_one("foobar-waldo.slice", "foobar.slice/foobar-waldo.slice", 0);
        test_slice_to_path_one("foobar-waldo.service", NULL, -EINVAL);
        test_slice_to_path_one("-.slice", NULL, -EINVAL);
        test_slice_to_path_one("-foo-.slice", NULL, -EINVAL);
        test_slice_to_path_one("-foo.slice", NULL, -EINVAL);
        test_slice_to_path_one("a-b.slice", "a.slice/a-b.slice", 0);
        test_slice_to_path_one("a-b-c-d-e.slice", "a.slice/a-b.slice/a-b-c.slice/a-b-c-d.slice/a-b-c-d-e.slice", 0);
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
        test_shift_path_one("/foobar/waldo", "/fuckfuck", "/foobar/waldo");
}

int main(void) {
        test_path_decode_unit();
        test_path_get_unit();
        test_path_get_user_unit();
        test_path_get_session();
        test_path_get_owner_uid();
        TEST_REQ_RUNNING_SYSTEMD(test_get_paths());
        test_proc();
        TEST_REQ_RUNNING_SYSTEMD(test_escape());
        test_controller_is_valid();
        test_slice_to_path();
        test_shift_path();

        return 0;
}
