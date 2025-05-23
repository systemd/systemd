/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_AUDIT
#  include <libaudit.h>         /* IWYU pragma: export */
#endif

#include "forward.h"

bool use_audit(void);

int close_audit_fd(int fd);
int open_audit_fd_or_warn(void);
