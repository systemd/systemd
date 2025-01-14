/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_AUDIT
#  include <libaudit.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "errno-util.h"
#include "log.h"
#include "pidref.h"

#define AUDIT_SESSION_INVALID UINT32_MAX

int audit_session_from_pid(const PidRef *pid, uint32_t *ret_id);
int audit_loginuid_from_pid(const PidRef *pid, uid_t *ret_uid);

bool use_audit(void);

static inline bool audit_session_is_valid(uint32_t id) {
        return id > 0 && id != AUDIT_SESSION_INVALID;
}

/* The wrappers for audit_open() and audit_close() are inline functions so that we don't get a spurious
 * linkage to libaudit in libbasic, but we also don't need to create a separate source file for two very
 * short functions. */

static inline int close_audit_fd(int fd) {
#if HAVE_AUDIT
        if (fd >= 0)
                audit_close(fd);
#else
        assert(fd < 0);
#endif
        return -EBADF;
}

static inline int open_audit_fd_or_warn(void) {
        int fd = -EBADF;

#if HAVE_AUDIT
        /* If the kernel lacks netlink or audit support, don't worry about it. */
        fd = audit_open();
        if (fd < 0)
                return log_full_errno(ERRNO_IS_NOT_SUPPORTED(errno) ? LOG_DEBUG : LOG_WARNING,
                                      errno, "Failed to connect to audit log, ignoring: %m");
#endif
        return fd;
}
