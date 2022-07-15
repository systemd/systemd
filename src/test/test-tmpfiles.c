/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "util.h"

TEST(tmpfiles) {
        _cleanup_free_ char *cmd = NULL, *cmd2 = NULL, *ans = NULL, *ans2 = NULL, *d = NULL, *tmp = NULL, *line = NULL;
        _cleanup_close_ int fd = -1, fd2 = -1;
        const char *p = saved_argv[1] ?: "/tmp";
        char *pattern;

        pattern = strjoina(p, "/systemd-test-XXXXXX");

        fd = open_tmpfile_unlinkable(p, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        assert_se(asprintf(&cmd, "ls -l /proc/"PID_FMT"/fd/%d", getpid_cached(), fd) > 0);
        (void) system(cmd);
        assert_se(readlink_malloc(cmd + 6, &ans) >= 0);
        log_debug("link1: %s", ans);
        assert_se(endswith(ans, " (deleted)"));

        fd2 = mkostemp_safe(pattern);
        assert_se(fd2 >= 0);
        assert_se(unlink(pattern) == 0);

        assert_se(asprintf(&cmd2, "ls -l /proc/"PID_FMT"/fd/%d", getpid_cached(), fd2) > 0);
        (void) system(cmd2);
        assert_se(readlink_malloc(cmd2 + 6, &ans2) >= 0);
        log_debug("link2: %s", ans2);
        assert_se(endswith(ans2, " (deleted)"));

        pattern = strjoina(p, "/tmpfiles-test");
        assert_se(tempfn_random(pattern, NULL, &d) >= 0);

        fd = safe_close(fd);
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
}

DEFINE_TEST_MAIN(LOG_DEBUG);
