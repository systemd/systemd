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

static void check_p_d_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;

        assert_se(cg_path_decode_unit(path, &unit) == code);
        assert_se(streq_ptr(unit, result));
}

static void test_path_decode_unit(void) {
        check_p_d_u("getty@.service/getty@tty2.service", 0, "getty@tty2.service");
        check_p_d_u("getty@.service/getty@tty2.service/xxx", 0, "getty@tty2.service");
        check_p_d_u("getty@.service/", -EINVAL, NULL);
        check_p_d_u("getty@.service", -EINVAL, NULL);
        check_p_d_u("getty.service", 0, "getty.service");
        check_p_d_u("getty", -EINVAL, NULL);
}

static void check_p_g_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;

        assert_se(cg_path_get_unit(path, &unit) == code);
        assert_se(streq_ptr(unit, result));
}

static void check_p_g_u_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;

        assert_se(cg_path_get_user_unit(path, &unit) == code);
        assert_se(streq_ptr(unit, result));
}

static void test_path_get_unit(void) {
        check_p_g_u("/system/foobar.service/sdfdsaf", 0, "foobar.service");
        check_p_g_u("/system/getty@.service/getty@tty5.service", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@.service/getty@tty5.service/aaa/bbb", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@.service/getty@tty5.service/", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@tty6.service/tty5", 0, "getty@tty6.service");
        check_p_g_u("sadfdsafsda", -ENOENT, NULL);
        check_p_g_u("/system/getty####@tty6.service/tty5", -EINVAL, NULL);
}

static void test_path_get_user_unit(void) {
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service/waldo", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service/waldo/uuuux", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/waldo/waldo/uuuux", -EINVAL, NULL);
        check_p_g_u_u("/user/lennart/2/foobar.service", -ENOENT, NULL);
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar@.service/foobar@pie.service/pa/po", 0, "foobar@pie.service");
}

static void test_get_paths(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL;

        assert_se(cg_get_root_path(&a) >= 0);
        log_info("Root = %s", a);

        assert_se(cg_get_system_path(&b) >= 0);
        log_info("System = %s", b);

        assert_se(cg_get_user_path(&c) >= 0);
        log_info("User = %s", c);

        assert_se(cg_get_machine_path("harley", &d) >= 0);
        log_info("Machine = %s", d);
}

static void test_proc(void) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        d = opendir("/proc");
        assert_se(d);

        FOREACH_DIRENT(de, d, break) {
                _cleanup_free_ char *path = NULL, *path_shifted = NULL, *session = NULL, *unit = NULL, *user_unit = NULL, *machine = NULL, *prefix = NULL;
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
                cg_pid_get_path_shifted(pid, &prefix, &path_shifted);
                cg_pid_get_owner_uid(pid, &uid);
                cg_pid_get_session(pid, &session);
                cg_pid_get_unit(pid, &unit);
                cg_pid_get_user_unit(pid, &user_unit);
                cg_pid_get_machine_name(pid, &machine);

                printf("%lu\t%s\t%s\t%s\t%lu\t%s\t%s\t%s\t%s\n",
                       (unsigned long) pid,
                       path,
                       prefix,
                       path_shifted,
                       (unsigned long) uid,
                       session,
                       unit,
                       user_unit,
                       machine);
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
        test_escape_one("cpu.service", "_cpu.service");
        test_escape_one("tasks", "_tasks");
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

int main(void) {
        test_path_decode_unit();
        test_path_get_unit();
        test_path_get_user_unit();
        test_get_paths();
        test_proc();
        test_escape();
        test_controller_is_valid();

        return 0;
}
