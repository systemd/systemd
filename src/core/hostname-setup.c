/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "util.h"

int hostname_setup(void) {
        _cleanup_free_ char *b = NULL;
        bool enoent = false;
        const char *hn;
        int r;

        r = read_etc_hostname(NULL, &b);
        if (r < 0) {
                if (r == -ENOENT)
                        enoent = true;
                else
                        log_warning_errno(r, "Failed to read configured hostname: %m");

                hn = NULL;
        } else
                hn = b;

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set
                 * and not explicitly configured */
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
