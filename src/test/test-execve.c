/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "strv.h"

static int run(int argc, char **argv) {
        _cleanup_close_ int fd;
        const char *path = argv[1] ?: "/bin/true";
        char **args = strv_skip(argv, 1);
        int r;

        args = !strv_isempty(args) ? args : STRV_MAKE("/bin/true");

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "open(%s) failed: %m", path);

        r = fexecve_or_execve(fd, path, args, NULL);
        assert(r < 0);
        return log_error_errno(r, "fexecve_or_execve(%s) failed: %m", path);
}

DEFINE_MAIN_FUNCTION(run);
