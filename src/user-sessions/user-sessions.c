/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "reboot-util.h"
#include "selinux-util.h"
#include "string-util.h"

static int run(int argc, char *argv[]) {
        int r;

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires one argument.");

        log_setup();

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        /* We only touch /run/nologin. See create_shutdown_run_nologin_or_warn() for details. */

        if (streq(argv[1], "start"))
                return unlink_or_warn("/run/nologin");
        if (streq(argv[1], "stop"))
                return create_shutdown_run_nologin_or_warn();

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb '%s'.", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
