/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "audit-fd.h"

#if HAVE_AUDIT

#include <libaudit.h>
#include <stdbool.h>

#include "capability-util.h"
#include "fd-util.h"
#include "log.h"
#include "util.h"

static bool initialized = false;
static int audit_fd;

int get_audit_fd(void) {

        if (!initialized) {
                if (have_effective_cap(CAP_AUDIT_WRITE) == 0) {
                        audit_fd = -EPERM;
                        initialized = true;

                        return audit_fd;
                }

                audit_fd = audit_open();

                if (audit_fd < 0) {
                        if (!IN_SET(errno, EAFNOSUPPORT, EPROTONOSUPPORT))
                                log_error_errno(errno, "Failed to connect to audit log: %m");

                        audit_fd = errno ? -errno : -EINVAL;
                }

                initialized = true;
        }

        return audit_fd;
}

void close_audit_fd(void) {

        if (initialized && audit_fd >= 0)
                safe_close(audit_fd);

        initialized = true;
        audit_fd = -ECONNRESET;
}

#else

int get_audit_fd(void) {
        return -EAFNOSUPPORT;
}

void close_audit_fd(void) {
}

#endif
