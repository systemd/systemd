/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "coredump-backtrace.h"
#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-kernel-helper.h"
#include "coredump-receive.h"
#include "coredump-util.h"
#include "log.h"
#include "main-func.h"
#include "string-util.h"

static int run(int argc, char *argv[]) {
        int r;

        /* First, log to a safe place, since we don't know what crashed and it might
         * be journald which we'd rather not log to then. */

        log_set_target_and_open(LOG_TARGET_KMSG);

        /* Make sure we never enter a loop */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        /* Ignore all parse errors */
        (void) coredump_parse_config();

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we
         * are invoked from the kernel as coredump handler. */
        if (r == 0) {
                if (streq_ptr(argv[1], "--backtrace"))
                        return coredump_backtrace(argc, argv);
                else
                        return coredump_kernel_helper(argc, argv);
        } else if (r == 1)
                return coredump_receive(SD_LISTEN_FDS_START);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Received unexpected number of file descriptors.");
}

DEFINE_MAIN_FUNCTION(run);
