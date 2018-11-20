/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <unistd.h>

#include "fileio.h"
#include "fileio-label.h"
#include "fs-util.h"
#include "main-func.h"
#include "log.h"
#include "selinux-util.h"
#include "string-util.h"
#include "util.h"

static int run(int argc, char*argv[]) {
        int r, k;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return -EINVAL;
        }

        log_setup_service();

        umask(0022);

        mac_selinux_init();

        if (streq(argv[1], "start")) {
                r = unlink_or_warn("/run/nologin");
                k = unlink_or_warn("/etc/nologin");
                if (r < 0)
                        return r;
                return k;

        } else if (streq(argv[1], "stop"))
                return create_shutdown_run_nologin_or_warn();

        log_error("Unknown verb '%s'.", argv[1]);
        return -EINVAL;
}

DEFINE_MAIN_FUNCTION(run);
