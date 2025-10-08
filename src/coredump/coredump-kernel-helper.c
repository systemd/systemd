/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-messages.h"

#include "coredump-context.h"
#include "coredump-kernel-helper.h"
#include "coredump-send.h"
#include "coredump-submit.h"
#include "coredump-util.h"
#include "fd-util.h"
#include "iovec-wrapper.h"
#include "log.h"
#include "namespace-util.h"
#include "signal-util.h"

int coredump_kernel_helper(int argc, char *argv[]) {
        _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = NULL;
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        /* When we're invoked by the kernel, stdout/stderr are closed which is dangerous because the fds
         * could get reallocated. To avoid hard to debug issues, let's instead bind stdout/stderr to
         * /dev/null. */
        r = rearrange_stdio(STDIN_FILENO, -EBADF, -EBADF);
        if (r < 0)
                return log_error_errno(r, "Failed to connect stdout/stderr to /dev/null: %m");

        log_debug("Processing coredump received from the kernel...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        /* Collect all process metadata passed by the kernel through argv[] */
        r = gather_pid_metadata_from_argv(iovw, &context, argc - 1, argv + 1);
        if (r < 0)
                return r;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata_from_procfs(iovw, &context);
        if (r < 0)
                return r;

        if (!context.is_journald)
                /* OK, now we know it's not the journal, hence we can make use of it now. */
                log_set_target_and_open(LOG_TARGET_JOURNAL_OR_KMSG);

        /* Log minimal metadata now, so it is not lost if the system is about to shut down. */
        log_info("Process %s (%s) of user %s terminated abnormally with signal %s/%s, processing...",
                 context.meta[META_ARGV_PID], context.meta[META_COMM],
                 context.meta[META_ARGV_UID], context.meta[META_ARGV_SIGNAL],
                 signal_to_string(context.signo));

        r = pidref_in_same_namespace(/* pid1 = */ NULL, &context.pidref, NAMESPACE_PID);
        if (r < 0)
                log_debug_errno(r, "Failed to check pidns of crashing process, ignoring: %m");
        if (r == 0) {
                /* If this fails, fallback to the old behavior so that
                 * there is still some record of the crash. */
                r = coredump_send_to_container(&context);
                if (r >= 0)
                        return 0;

                r = acquire_pid_mount_tree_fd(&context, &context.mount_tree_fd);
                if (r < 0)
                        log_warning_errno(r, "Failed to access the mount tree of a container, ignoring: %m");
        }

        /* If this is PID 1, disable coredump collection, we'll unlikely be able to process
         * it later on.
         *
         * FIXME: maybe we should disable coredumps generation from the beginning and
         * re-enable it only when we know it's either safe (i.e. we're not running OOM) or
         * it's not PID 1 ? */
        if (context.is_pid1) {
                log_notice("Due to PID 1 having crashed coredump collection will now be turned off.");
                disable_coredumps();
        }

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_COREDUMP_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        if (context.is_journald || context.is_pid1)
                return coredump_submit(&context, iovw, STDIN_FILENO);

        return coredump_send(iovw, STDIN_FILENO, &context.pidref, context.mount_tree_fd);
}
