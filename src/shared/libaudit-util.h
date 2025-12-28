/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dlopen_libaudit(void);

#if HAVE_AUDIT
#  include <libaudit.h>         /* IWYU pragma: export */

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(audit_log_acct_message);
extern DLSYM_PROTOTYPE(audit_log_user_avc_message);
extern DLSYM_PROTOTYPE(audit_log_user_comm_message);
#endif

bool use_audit(void);

int close_audit_fd(int fd);
int open_audit_fd_or_warn(void);
