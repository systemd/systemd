/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "coredump-backtrace.h"
#include "coredump-kernel-helper.h"
#include "coredump-receive.h"
#include "coredump-util.h"
#include "dlopen-note.h"
#include "errno-util.h"
#include "log.h"
#include "main-func.h"
#include "pidfd-util.h"
#include "string-util.h"

static int run(int argc, char *argv[]) {
        int r;

        COMPRESS_DEFAULT_NOTE;
        LIBACL_NOTE(recommended);
        LIBDW_NOTE(suggested);
        LIBELF_NOTE(suggested);
        LIBSELINUX_NOTE(recommended);

        if (streq_ptr(argv[1], "--check-pidfd-features")) {
                /* This checks the following flags are supported by the running kernel:
                 * PIDFD_INFO_COREDUMP        : 1d8db6fd698de1f73b1a7d72aea578fdd18d9a87 (v6.16),
                 * PIDFD_INFO_COREDUMP_SIGNAL : 036375522be8425874e9e0f907c7127e315c7a52 (v6.19).
                 *
                 * These flags are required for using the kernel coredump socket feature. Note that the
                 * request mode coredump socket pattern (@@ prefixed) is supported since kernel v6.17. Old
                 * kernels do not refuse the new core patterns (moreover, any strings are accepted), hence we
                 * need to check kernel version in some ways other than reading/writing core patterns. This
                 * method can be also used for checking that. If the required flags are supported, we assume
                 * the kernel is new enough, and the kernel coredump socket is also supported. */

                r = pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP | PIDFD_INFO_COREDUMP_SIGNAL);
                if (IN_SET(r, 0, -EOPNOTSUPP))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "ioctl(PIDFD_GET_INFO) does not support PIDFD_INFO_COREDUMP and/or PIDFD_INFO_COREDUMP_SIGNAL.");
                if (r < 0)
                        return log_error_errno(r, "Failed to check if PIDFD_INFO_COREDUMP and PIDFD_INFO_COREDUMP_SIGNAL flags are supported by ioctl(PIDFD_GET_INFO): %m");

                log_debug("The kernel supports both PIDFD_INFO_COREDUMP and PIDFD_INFO_COREDUMP_SIGNAL, assuming the kernel coredump socket is also supported.");
                return 0;
        }

        /* When running as backtrace mode, it is not necessary to use kmsg, not necessary to disable coredump
         * from the command, and unexpectedly passed file descriptors can be silently ignored. */
        if (streq_ptr(argv[1], "--backtrace"))
                return coredump_backtrace(argc, argv);

        /* First, log to a safe place, since we don't know what crashed and it might be journald which we'd
         * rather not log to then. */
        log_parse_environment();
        log_set_target_and_open(LOG_TARGET_KMSG);

        /* Make sure we never enter a loop. */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we are invoked from the
         * kernel as coredump handler. */
        if (r == 0)
                return coredump_kernel_helper(argc, argv);
        if (r == 1)
                return coredump_receive(SD_LISTEN_FDS_START);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Received unexpected number of file descriptors.");
}

DEFINE_MAIN_FUNCTION(run);
