/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "fileio-label.h"
#include "fileio.h"
#include "selinux-util.h"

int write_string_file_atomic_label_ts(const char *fn, const char *line, struct timespec *ts) {
        int r;

        r = mac_selinux_create_file_prepare(fn, S_IFREG);
        if (r < 0)
                return r;

        r = write_string_file_ts(fn, line, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC, ts);

        mac_selinux_create_file_clear();

        return r;
}

int create_shutdown_run_nologin_or_warn(void) {
        int r;

        /* This is used twice: once in systemd-user-sessions.service, in order to block logins when we actually go
         * down, and once in systemd-logind.service when shutdowns are scheduled, and logins are to be turned off a bit
         * in advance. We use the same wording of the message in both cases. */

        r = write_string_file_atomic_label("/run/nologin",
                                           "System is going down. Unprivileged users are not permitted to log in anymore. "
                                           "For technical details, see pam_nologin(8).");
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/nologin: %m");

        return 0;
}
