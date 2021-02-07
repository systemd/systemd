/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "env-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "strv.h"
#include "systemctl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_strv_free_ char **argv = NULL;
        _cleanup_free_ char *orig_stdout = NULL;
        int r;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        arg_pager_flags = PAGER_DISABLE; /* We shouldn't execute the pager */

        argv = strv_parse_nulstr((const char *)data, size);
        if (!argv)
                return log_oom();

        if (!argv[0])
                return 0; /* argv[0] should always be present, but may be zero-length. */

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0) {
                r = readlink_malloc("/proc/self/fd/1", &orig_stdout);
                if (r < 0)
                        log_warning_errno(r, "Cannot readlink /proc/self/fd/1: %m");
                else
                        assert_se(freopen("/dev/null", "w", stdout));
        }

        optind = 1;

        r = systemctl_dispatch_parse_argv(strv_length(argv), argv);
        if (r < 0)
                log_error_errno(r, "Failed to parse args: %m");
        else
                log_info(r == 0 ? "Done!" : "Action!");

        if (orig_stdout)
                assert_se(freopen(orig_stdout, "w", stdout));

        return 0;
}
