/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "log.h"
#include "raw-reboot.h"
#include "reboot-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "virt.h"

int update_reboot_parameter_and_warn(const char *parameter, bool keep) {
        int r;

        if (isempty(parameter)) {
                if (keep)
                        return 0;

                if (unlink("/run/systemd/reboot-param") < 0) {
                        if (errno == ENOENT)
                                return 0;

                        return log_warning_errno(errno, "Failed to unlink reboot parameter file: %m");
                }

                return 0;
        }

        RUN_WITH_UMASK(0022) {
                r = write_string_file("/run/systemd/reboot-param", parameter,
                                      WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        return log_warning_errno(r, "Failed to write reboot parameter file: %m");
        }

        return 0;
}

int read_reboot_parameter(char **parameter) {
        int r;

        assert(parameter);

        r = read_one_line_file("/run/systemd/reboot-param", parameter);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to read /run/systemd/reboot-param: %m");

        return 0;
}

int reboot_with_parameter(RebootFlags flags) {
        int r;

        /* Reboots the system with a parameter that is read from /run/systemd/reboot-param. Returns 0 if REBOOT_DRY_RUN
         * was set and the actual reboot operation was hence skipped. If REBOOT_FALLBACK is set and the reboot with
         * parameter doesn't work out a fallback to classic reboot() is attempted. If REBOOT_FALLBACK is not set, 0 is
         * returned instead, which should be considered indication for the caller to fall back to reboot() on its own,
         * or somehow else deal with this. If REBOOT_LOG is specified will log about what it is going to do, as well as
         * all errors. */

        if (detect_container() == 0) {
                _cleanup_free_ char *parameter = NULL;

                r = read_one_line_file("/run/systemd/reboot-param", &parameter);
                if (r < 0 && r != -ENOENT)
                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, r,
                                       "Failed to read reboot parameter file, ignoring: %m");

                if (!isempty(parameter)) {

                        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG,
                                 "Rebooting with argument '%s'.", parameter);

                        if (flags & REBOOT_DRY_RUN)
                                return 0;

                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, parameter);

                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, errno,
                                       "Failed to reboot with parameter, retrying without: %m");
                }
        }

        if (!(flags & REBOOT_FALLBACK))
                return 0;

        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG, "Rebooting.");

        if (flags & REBOOT_DRY_RUN)
                return 0;

        (void) reboot(RB_AUTOBOOT);

        return log_full_errno(flags & REBOOT_LOG ? LOG_ERR : LOG_DEBUG, errno, "Failed to reboot: %m");
}
