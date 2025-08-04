/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "creds-util.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "string-table.h"
#include "string-util.h"

typedef enum QuotaCheckMode {
        QUOTA_CHECK_AUTO,
        QUOTA_CHECK_FORCE,
        QUOTA_CHECK_SKIP,
        _QUOTA_CHECK_MODE_MAX,
        _QUOTA_CHECK_MODE_INVALID = -EINVAL,
} QuotaCheckMode;

static QuotaCheckMode arg_mode = QUOTA_CHECK_AUTO;

static const char * const quota_check_mode_table[_QUOTA_CHECK_MODE_MAX] = {
        [QUOTA_CHECK_AUTO]  = "auto",
        [QUOTA_CHECK_FORCE] = "force",
        [QUOTA_CHECK_SKIP]  = "skip",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(quota_check_mode, QuotaCheckMode);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {

        if (streq(key, "quotacheck.mode")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                arg_mode = quota_check_mode_from_string(value);
                if (arg_mode < 0)
                        log_warning_errno(arg_mode, "Invalid quotacheck.mode= value, ignoring: %s", value);

        } else if (streq(key, "forcequotacheck") && !value)
                arg_mode = QUOTA_CHECK_FORCE;

        return 0;
}

static void parse_credentials(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        r = read_credential("quotacheck.mode", (void**) &value, /* ret_size = */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential 'quotacheck.mode', ignoring: %m");
        else {
                arg_mode = quota_check_mode_from_string(value);
                if (arg_mode < 0)
                        log_warning_errno(arg_mode, "Invalid 'quotacheck.mode' credential, ignoring: %s", value);
        }
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

        parse_credentials();

        if (arg_mode == QUOTA_CHECK_SKIP)
                return 0;

        if (arg_mode == QUOTA_CHECK_AUTO) {
                /* This is created by systemd-fsck when fsck detected and corrected errors. In normal
                 * operations quotacheck is not needed. */
                if (access("/run/systemd/quotacheck", F_OK) < 0) {
                        if (errno != ENOENT)
                                log_warning_errno(errno,
                                                  "Failed to check whether /run/systemd/quotacheck exists, ignoring: %m");

                        return 0;
                }
        }

        _cleanup_free_ char *path = NULL;
        if (argc == 2) {
                path = strdup(argv[1]);
                if (!path)
                        return log_oom();
        }

        r = safe_fork("(quotacheck)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_WAIT|FORK_LOG, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmdline[] = {
                        QUOTACHECK,
                        path ? "-nug" : "-anug", /* Check all file systems if path isn't specified */
                        path,
                        NULL
                };

                /* Child */

                execv(cmdline[0], (char**) cmdline);
                _exit(EXIT_FAILURE); /* Operational error */
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
