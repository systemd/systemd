/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "reread-partition-table.h"

static int run(int argc, char *argv[]) {
        int r;

        log_set_max_level(LOG_DEBUG);
        log_setup();

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected single parameter, the device node to open.");

        _cleanup_close_ int fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", argv[1]);

        r = reread_partition_table_fd(fd, REREADPT_BSD_LOCK|REREADPT_FORCE_UEVENT);
        if (r < 0)
                return log_error_errno(r, "Failed to reread partition table: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
