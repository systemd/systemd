/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "audit-fd.h"

#if HAVE_AUDIT
#  include <stdbool.h>

#  include "audit-util.h"
#  include "capability-util.h"

static bool initialized = false;
static int audit_fd = -EBADF;
#endif

int get_core_audit_fd(void) {
#if HAVE_AUDIT
        if (!initialized) {
                if (have_effective_cap(CAP_AUDIT_WRITE) <= 0)
                        audit_fd = -EPERM;
                else
                        audit_fd = open_audit_fd_or_warn();

                initialized = true;
        }

        return audit_fd;
#else
        return -EAFNOSUPPORT;
#endif
}

void close_core_audit_fd(void) {
#if HAVE_AUDIT
        close_audit_fd(audit_fd);
        initialized = true;
        audit_fd = -ECONNRESET;
#endif
}
