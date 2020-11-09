/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "util.h"

int hostname_setup(void) {
        _cleanup_free_ char *b = NULL;
        const char *hn = NULL;
        bool enoent = false;
        int r;

        r = proc_cmdline_get_key("systemd.hostname", 0, &b);
        if (r < 0)
                log_warning_errno(r, "Failed to retrieve system hostname from kernel command line, ignoring: %m");
        else if (r > 0) {
                if (hostname_is_valid(b, true))
                        hn = b;
                else  {
                        log_warning("Hostname specified on kernel command line is invalid, ignoring: %s", b);
                        b = mfree(b);
                }
        }

        if (!hn) {
                r = read_etc_hostname(NULL, &b);
                if (r < 0) {
                        if (r == -ENOENT)
                                enoent = true;
                        else
                                log_warning_errno(r, "Failed to read configured hostname: %m");
                } else
                        hn = b;
        }

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set and not explicitly configured */
                if (hostname_is_set())
                        return 0;

                if (enoent)
                        log_info("No hostname configured.");

                hn = FALLBACK_HOSTNAME;
        }

        r = sethostname_idempotent(hn);
        if (r < 0)
                return log_warning_errno(r, "Failed to set hostname to <%s>: %m", hn);

        log_info("Set hostname to <%s>.", hn);
        return 0;
}
