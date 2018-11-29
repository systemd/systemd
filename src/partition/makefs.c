/***
  SPDX-License-Identifier: LGPL-2.1+
***/

#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dissect-image.h"
#include "main-func.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"

static int makefs(const char *type, const char *device) {
        const char *mkfs;
        pid_t pid;
        int r;

        if (streq(type, "swap"))
                mkfs = "/sbin/mkswap";
        else
                mkfs = strjoina("/sbin/mkfs.", type);
        if (access(mkfs, X_OK) != 0)
                return log_error_errno(errno, "%s is not executable: %m", mkfs);

        r = safe_fork("(mkfs)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmdline[3] = { mkfs, device, NULL };

                /* Child */

                execv(cmdline[0], (char**) cmdline);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(mkfs, pid, WAIT_LOG);
}

static int run(int argc, char *argv[]) {
        const char *device, *type;
        _cleanup_free_ char *detected = NULL;
        struct stat st;
        int r;

        log_setup_service();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program expects two arguments.");

        type = argv[1];
        device = argv[2];

        if (stat(device, &st) < 0)
                return log_error_errno(errno, "Failed to stat \"%s\": %m", device);

        if (!S_ISBLK(st.st_mode))
                log_info("%s is not a block device.", device);

        r = probe_filesystem(device, &detected);
        if (r < 0)
                return log_warning_errno(r,
                                         r == -EUCLEAN ?
                                         "Cannot reliably determine probe \"%s\", refusing to proceed." :
                                         "Failed to probe \"%s\": %m",
                                         device);

        if (detected) {
                log_info("%s is not empty (type %s), exiting", device, detected);
                return 0;
        }

        return makefs(type, device);
}

DEFINE_MAIN_FUNCTION(run);
