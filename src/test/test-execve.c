/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "strv.h"
#include "tests.h"

/* This program can be used to call programs through fexecve / execveat(…, "", …, AT_EMPTY_PATH),
 * when compiled with -Dfexecve=true, and the fallback paths, when -Dfexecve=false.
 *
 * Example:
 * $ strace -e execveat build/test-execve /bin/grep Name /proc/self/status
 * execveat(3, "", ["/bin/grep", "Name", "/proc/self/status"], NULL, AT_EMPTY_PATH) = 0
 * Name:   3
 *
 * FIXME: use the new kernel api to set COMM properly when the kernel makes that available.
 * C.f. ceedbf8185fc7593366679f02d31da63af8c4bd1.
 */

static int run(int argc, char **argv) {
        _cleanup_close_ int fd = -EBADF;
        char **args = strv_skip(argv, 1);
        int r;

        test_setup_logging(LOG_DEBUG);

        args = !strv_isempty(args) ? args : STRV_MAKE("/bin/true");

        fd = open(args[0], O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "open(%s) failed: %m", args[0]);

        r = fexecve_or_execve(fd, args[0], args, NULL);
        assert_se(r < 0);
        return log_error_errno(r, "fexecve_or_execve(%s) failed: %m", args[0]);
}

DEFINE_MAIN_FUNCTION(run);
