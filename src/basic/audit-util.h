/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define AUDIT_SESSION_INVALID ((uint32_t) -1)

int audit_session_from_pid(pid_t pid, uint32_t *id);
int audit_loginuid_from_pid(pid_t pid, uid_t *uid);

bool use_audit(void);

static inline bool audit_session_is_valid(uint32_t id) {
        return id > 0 && id != AUDIT_SESSION_INVALID;
}
