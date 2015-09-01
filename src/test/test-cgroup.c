/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <unistd.h>
#include <string.h>

#include "cgroup-util.h"
#include "path-util.h"
#include "util.h"

int main(int argc, char*argv[]) {
        char *path;
        char *c, *p;

        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, "/test-a") == 0);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, "/test-a") == 0);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, "/test-b") == 0);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, "/test-b/test-c") == 0);
        assert_se(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, "/test-b", 0) == 0);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid(), &path) == 0);
        assert_se(streq(path, "/test-b"));
        free(path);

        assert_se(cg_attach(SYSTEMD_CGROUP_CONTROLLER, "/test-a", 0) == 0);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid(), &path) == 0);
        assert_se(path_equal(path, "/test-a"));
        free(path);

        assert_se(cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, "/test-b/test-d", 0) == 0);

        assert_se(cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, getpid(), &path) == 0);
        assert_se(path_equal(path, "/test-b/test-d"));
        free(path);

        assert_se(cg_get_path(SYSTEMD_CGROUP_CONTROLLER, "/test-b/test-d", NULL, &path) == 0);
        assert_se(path_equal(path, "/sys/fs/cgroup/systemd/test-b/test-d"));
        free(path);

        assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, "/test-a") > 0);
        assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, "/test-b") > 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-a") > 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-b") == 0);

        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-a", 0, false, false, false, NULL) == 0);
        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-b", 0, false, false, false, NULL) > 0);

        assert_se(cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-b", SYSTEMD_CGROUP_CONTROLLER, "/test-a", false, false) > 0);

        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-a") == 0);
        assert_se(cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-b") > 0);

        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-a", 0, false, false, false, NULL) > 0);
        assert_se(cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, "/test-b", 0, false, false, false, NULL) == 0);

        cg_trim(SYSTEMD_CGROUP_CONTROLLER, "/", false);

        assert_se(cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, "/test-b") < 0);
        assert_se(cg_rmdir(SYSTEMD_CGROUP_CONTROLLER, "/test-a") >= 0);

        assert_se(cg_split_spec("foobar:/", &c, &p) == 0);
        assert_se(streq(c, "foobar"));
        assert_se(streq(p, "/"));
        free(c);
        free(p);

        assert_se(cg_split_spec("foobar:", &c, &p) < 0);
        assert_se(cg_split_spec("foobar:asdfd", &c, &p) < 0);
        assert_se(cg_split_spec(":///", &c, &p) < 0);
        assert_se(cg_split_spec(":", &c, &p) < 0);
        assert_se(cg_split_spec("", &c, &p) < 0);
        assert_se(cg_split_spec("fo/obar:/", &c, &p) < 0);

        assert_se(cg_split_spec("/", &c, &p) >= 0);
        assert_se(c == NULL);
        assert_se(streq(p, "/"));
        free(p);

        assert_se(cg_split_spec("foo", &c, &p) >= 0);
        assert_se(streq(c, "foo"));
        assert_se(p == NULL);
        free(c);

        return 0;
}
