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

static void check_c_t_u(const char *path, int code, const char *result) {
        _cleanup_free_ char *unit = NULL;

        assert_se(cg_cgroup_to_unit(path, &unit) == code);
        assert_se(streq_ptr(unit, result));
}

static void test_cgroup_to_unit(void) {
        check_c_t_u("getty@.service/tty2", 0, "getty@tty2.service");
        check_c_t_u("getty@.service/tty2/xxx", 0, "getty@tty2.service");
        check_c_t_u("getty@.service/", -EINVAL, NULL);
        check_c_t_u("getty@.service", -EINVAL, NULL);
        check_c_t_u("getty.service", 0, "getty.service");
        check_c_t_u("getty", -EINVAL, NULL);
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
        check_p_g_u("/system/getty@.service/tty5", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@.service/tty5/aaa/bbb", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@.service/tty5/", 0, "getty@tty5.service");
        check_p_g_u("/system/getty@tty6.service/tty5", 0, "getty@tty6.service");
        check_p_g_u("sadfdsafsda", -ENOENT, NULL);
        check_p_g_u("/system/getty####@tty6.service/tty5", -EINVAL, NULL);

        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service/waldo", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar.service/waldo/uuuux", 0, "foobar.service");
        check_p_g_u_u("/user/lennart/2/systemd-21548/waldo/waldo/uuuux", -EINVAL, NULL);
        check_p_g_u_u("/user/lennart/2/foobar.service", -ENOENT, NULL);
        check_p_g_u_u("/user/lennart/2/systemd-21548/foobar@.service/pie/pa/po", 0, "foobar@pie.service");
}

int main(void) {
        test_cgroup_to_unit();
        test_path_get_unit();

        return 0;
}
