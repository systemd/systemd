/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Michael Marineau

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

#include <stdarg.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "fs-util.h"
#include "macro.h"
#include "parse-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static void setup_test_dir(char *tmp_dir, const char *files, ...) {
        va_list ap;

        assert_se(mkdtemp(tmp_dir) != NULL);

        va_start(ap, files);
        while (files != NULL) {
                _cleanup_free_ char *path = strappend(tmp_dir, files);
                assert_se(touch_file(path, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) == 0);
                files = va_arg(ap, const char *);
        }
        va_end(ap);
}

static void test_conf_files_list(bool use_root) {
        char tmp_dir[] = "/tmp/test-conf-files-XXXXXX";
        _cleanup_strv_free_ char **found_files = NULL;
        const char *root_dir, *search_1, *search_2, *expect_a, *expect_b;

        setup_test_dir(tmp_dir,
                       "/dir1/a.conf",
                       "/dir2/a.conf",
                       "/dir2/b.conf",
                       NULL);

        if (use_root) {
                root_dir = tmp_dir;
                search_1 = "/dir1";
                search_2 = "/dir2";
        } else {
                root_dir = NULL;
                search_1 = strjoina(tmp_dir, "/dir1");
                search_2 = strjoina(tmp_dir, "/dir2");
        }

        expect_a = strjoina(tmp_dir, "/dir1/a.conf");
        expect_b = strjoina(tmp_dir, "/dir2/b.conf");

        assert_se(conf_files_list(&found_files, ".conf", root_dir, search_1, search_2, NULL) == 0);
        strv_print(found_files);

        assert_se(found_files);
        assert_se(streq_ptr(found_files[0], expect_a));
        assert_se(streq_ptr(found_files[1], expect_b));
        assert_se(found_files[2] == NULL);

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

int main(int argc, char **argv) {
        test_conf_files_list(false);
        test_conf_files_list(true);
        return 0;
}
