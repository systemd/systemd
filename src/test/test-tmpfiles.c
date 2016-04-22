/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "fs-util.h"
#include "log.h"
#include "string-util.h"
#include "util.h"

int main(int argc, char** argv) {
        _cleanup_free_ char *cmd = NULL, *cmd2 = NULL, *ans = NULL, *ans2 = NULL, *d = NULL, *tmp = NULL, *line = NULL;
        _cleanup_close_ int fd = -1, fd2 = -1, fd3 = -1;
        const char *p = argv[1] ?: "/tmp";
        char *pattern;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        pattern = strjoina(p, "/systemd-test-XXXXXX");

        fd = open_tmpfile_unlinkable(p, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        assert_se(asprintf(&cmd, "ls -l /proc/"PID_FMT"/fd/%d", getpid(), fd) > 0);
        (void) system(cmd);
        assert_se(readlink_malloc(cmd + 6, &ans) >= 0);
        log_debug("link1: %s", ans);
        assert_se(endswith(ans, " (deleted)"));

        fd2 = mkostemp_safe(pattern, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(unlink(pattern) == 0);

        assert_se(asprintf(&cmd2, "ls -l /proc/"PID_FMT"/fd/%d", getpid(), fd2) > 0);
        (void) system(cmd2);
        assert_se(readlink_malloc(cmd2 + 6, &ans2) >= 0);
        log_debug("link2: %s", ans2);
        assert_se(endswith(ans2, " (deleted)"));

        pattern = strjoina(p, "/tmpfiles-test");
        assert_se(tempfn_random(pattern, NULL, &d) >= 0);

        fd = open_tmpfile_linkable(d, O_RDWR|O_CLOEXEC, &tmp);
        assert_se(fd >= 0);
        assert_se(write(fd, "foobar\n", 7) == 7);

        assert_se(touch(d) >= 0);
        assert_se(link_tmpfile(fd, tmp, d) == -EEXIST);
        assert_se(unlink(d) >= 0);
        assert_se(link_tmpfile(fd, tmp, d) >= 0);

        assert_se(read_one_line_file(d, &line) >= 0);
        assert_se(streq(line, "foobar"));
        assert_se(unlink(d) >= 0);

        return 0;
}
