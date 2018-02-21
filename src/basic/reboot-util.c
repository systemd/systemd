/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <unistd.h>

#include "fileio.h"
#include "log.h"
#include "reboot-util.h"
#include "string-util.h"
#include "umask-util.h"

int update_reboot_parameter_and_warn(const char *parameter) {
        int r;

        if (isempty(parameter)) {
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
