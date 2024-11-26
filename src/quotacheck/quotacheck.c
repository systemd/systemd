/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "static-destruct.h"
#include "string-util.h"

static char *arg_path = NULL;
static bool arg_skip = false;
static bool arg_force = false;

STATIC_DESTRUCTOR_REGISTER(arg_path, freep);

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
                        log_warning("Invalid quotacheck.mode= value, ignoring: %s", value);

        } else if (streq(key, "forcequotacheck") && !value)
                arg_force = true;

        return 0;
}

static void test_files(void) {

#if HAVE_SYSV_COMPAT
        if (access("/forcequotacheck", F_OK) >= 0) {
                log_error("Please pass 'quotacheck.mode=force' on the kernel command line rather than creating /forcequotacheck on the root file system. Proceeding anyway.");
                arg_force = true;
        }
#endif
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program expects one or no arguments.");

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        test_files();

        if (!arg_force) {
                if (arg_skip)
                        return 0;

                /* This is created by systemd-fsck when fsck detected and corrected errors. In normal
                 * operations quotacheck is not needed. */
                if (access("/run/systemd/quotacheck", F_OK) < 0) {
                        if (errno != ENOENT)
                                log_warning_errno(errno,
                                                  "Failed to check whether /run/systemd/quotacheck exists, ignoring: %m");

                        return 0;
                }
        }

        if (argc == 2) {
                arg_path = strdup(argv[1]);
                if (!arg_path)
                        return log_oom();
        }

        r = safe_fork("(quotacheck)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_WAIT|FORK_LOG, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmdline[] = {
                        QUOTACHECK,
                        arg_path ? "-nug" : "-anug", /* Check all file systems if path isn't specified */
                        arg_path,
                        NULL
                };

                /* Child */

                execv(cmdline[0], (char**) cmdline);
                _exit(EXIT_FAILURE); /* Operational error */
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
