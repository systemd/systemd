/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-kernel-helper.h"
#include "coredump-send.h"
#include "coredump-submit.h"
#include "coredump-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "signal-util.h"

int coredump_kernel_helper(int argc, char *argv[]) {
        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        int r;

        /* When we're invoked by the kernel, stdout/stderr are closed which is dangerous because the fds
         * could get reallocated. To avoid hard to debug issues, let's instead bind stdout/stderr to
         * /dev/null. Also, move stdin to above stdio and then also bind stdin to /dev/null. */

        r = fd_move_above_stdio(STDIN_FILENO);
        if (r < 0)
                return log_error_errno(r, "Failed to move stdin above stdio: %m");
        context.input_fd = r;

        r = make_null_stdio();
        if (r < 0)
                return log_error_errno(r, "Failed to connect stdin/stdout/stderr to /dev/null: %m");

        /* Ignore all parse errors */
        CoredumpConfig config = COREDUMP_CONFIG_NULL;
        (void) coredump_parse_config(&config);

        log_debug("Processing coredump received from the kernel...");

        /* Collect all process metadata passed by the kernel through argv[] */
        r = coredump_context_parse_from_argv(&context, argc - 1, argv + 1);
        if (r < 0)
                return r;

        if (!coredump_context_is_journald(&context))
                /* OK, now we know it's not the journal, hence we can make use of it now. */
                log_set_target_and_open(LOG_TARGET_JOURNAL_OR_KMSG);

        /* Log minimal metadata now, so it is not lost if the system is about to shut down. */
        log_info("Process "PID_FMT" (%s) of user "UID_FMT" terminated abnormally with signal %i/%s, processing...",
                 context.pidref.pid, context.comm, context.uid, context.signo,
                 signal_to_string(context.signo));

        if (coredump_send_to_container(&context) > 0)
                return 0;

        /* If this is PID 1, disable coredump collection, we'll unlikely be able to process
         * it later on.
         *
         * FIXME: maybe we should disable coredumps generation from the beginning and
         * re-enable it only when we know it's either safe (i.e. we're not running OOM) or
         * it's not PID 1 ? */
        if (coredump_context_is_pid1(&context)) {
                log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                disable_coredumps();
        }

        if (coredump_context_is_journald(&context) || coredump_context_is_pid1(&context))
                return coredump_submit(&config, &context);

        r = coredump_context_build_iovw(&context);
        if (r < 0)
                return r;

        return coredump_send(&context);
}
