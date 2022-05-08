/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "env-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "selinux-util.h"
#include "static-destruct.h"
#include "stdio-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_strv_free_ char **argv = NULL;
        _cleanup_close_ int orig_stdout_fd = -1;
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
        if (strv_length(argv) > 1024)
                return 0; /* oss-fuzz reports timeouts which are caused by appending to a very long strv.
                           * The code is indeed not very efficient, but it's designed for normal command-line
                           * use, where we don't expect more than a dozen of entries. The fact that it is
                           * slow with ~100k entries is not particularly interesting. Let's just refuse such
                           * long command lines. */

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0) {
                orig_stdout_fd = fcntl(fileno(stdout), F_DUPFD_CLOEXEC, 3);
                if (orig_stdout_fd < 0)
                        log_warning_errno(orig_stdout_fd, "Failed to duplicate fd 1: %m");
                else
                        assert_se(freopen("/dev/null", "w", stdout));

                opterr = 0; /* do not print errors */
        }

        optind = 0; /* this tells the getopt machinery to reinitialize */

        r = systemctl_dispatch_parse_argv(strv_length(argv), argv);
        if (r < 0)
                log_error_errno(r, "Failed to parse args: %m");
        else
                log_info(r == 0 ? "Done!" : "Action!");

        if (orig_stdout_fd >= 0)
                assert_se(freopen(FORMAT_PROC_FD_PATH(orig_stdout_fd), "w", stdout));

        release_busses(); /* We open the bus for communication with logind.
                           * It needs to be closed to avoid apparent leaks. */

        mac_selinux_finish();

        /* Call static destructors to do global state cleanup. We do it here, and not in fuzz-main.c so that
         * any global state is destroyed between fuzzer runs. */
        static_destruct();

        return 0;
}
