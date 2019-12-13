/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "main-func.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "util.h"

static bool arg_skip = false;
static bool arg_force = false;

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {

        if (streq(key, "quotacheck.mode")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (streq(value, "auto"))
                        arg_force = arg_skip = false;
                else if (streq(value, "force"))
                        arg_force = true;
                else if (streq(value, "skip"))
                        arg_skip = true;
                else
                        log_warning("Invalid quotacheck.mode= parameter '%s'. Ignoring.", value);
        }

#if HAVE_SYSV_COMPAT
        else if (streq(key, "forcequotacheck") && !value) {
                log_warning("Please use 'quotacheck.mode=force' rather than 'forcequotacheck' on the kernel command line.");
                arg_force = true;
        }
#endif

        return 0;
}

static void test_files(void) {

#if HAVE_SYSV_COMPAT
        if (access("/forcequotacheck", F_OK) >= 0) {
                log_error("Please pass 'quotacheck.mode=force' on the kernel command line rather than creating /forcequotacheck on the root file system.");
                arg_force = true;
        }
#endif
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup_service();

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        test_files();

        if (!arg_force) {
                if (arg_skip)
                        return 0;

                if (access("/run/systemd/quotacheck", F_OK) < 0)
                        return 0;
        }

        r = safe_fork("(quotacheck)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_WAIT|FORK_LOG, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                static const char * const cmdline[] = {
                        QUOTACHECK,
                        "-anug",
                        NULL
                };

                /* Child */

                execv(cmdline[0], (char**) cmdline);
                _exit(EXIT_FAILURE); /* Operational error */
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
