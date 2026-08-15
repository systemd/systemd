/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "errno-util.h"
#include "fd-util.h"
#include "libarchive-util.h"
#include "main-func.h"
#include "tar-util.h"
#include "tests.h"

static int run(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        if (argc != 4)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need three arguments exactly: -c <output> <input> | -x <input> <output>");

        bool create;
        if (streq(argv[1], "-c"))
                create = true;
        else if (streq(argv[1], "-x"))
                create = false;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown operation '%s'.", argv[1]);

        r = dlopen_libarchive(LOG_DEBUG);
        if (r < 0)
                return r;

        int flags = create ? O_CREAT | O_WRONLY | O_TRUNC : O_RDONLY;
        _cleanup_close_ int fd1 = RET_NERRNO(open(argv[2], flags | O_CLOEXEC, 0666));
        if (fd1 < 0)
                return log_error_errno(fd1, "Cannot open %s: %m", argv[2]);

        if (!create) {
                r = RET_NERRNO(mkdir(argv[3], 0777));
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to mkdir %s: %m", argv[3]);
        }

        _cleanup_close_ int fd2 = RET_NERRNO(open(argv[3], O_DIRECTORY | O_CLOEXEC));
        if (fd2 < 0)
                return log_error_errno(fd2, "Cannot open %s: %m", argv[3]);

        if (create)
                r = tar_c(fd2, fd1, argv[2], /* flags= */ TAR_SELINUX);
        else
                r = tar_x(fd1, fd2, /* flags= */ TAR_SELINUX);
        if (r < 0)
                return log_error_errno(r, "tar %s failed: %m", argv[1]);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
