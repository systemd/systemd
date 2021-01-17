/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fileio.h"
#include "fileio-label.h"
#include "fs-util.h"
#include "main-func.h"
#include "log.h"
#include "selinux-util.h"
#include "string-util.h"

static int run(int argc, char *argv[]) {
        int r, k;

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires one argument.");

        log_setup();

        umask(0022);

        r = mac_selinux_init();
        if (r < 0)
                return r;

        if (streq(argv[1], "start")) {
                r = unlink_or_warn("/run/nologin");
                k = unlink_or_warn("/etc/nologin");
                if (r < 0)
                        return r;
                return k;

        } else if (streq(argv[1], "stop"))
                return create_shutdown_run_nologin_or_warn();

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb '%s'.", argv[1]);
}

DEFINE_MAIN_FUNCTION(run);
