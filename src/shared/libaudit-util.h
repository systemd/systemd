/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool use_audit(void);

int close_audit_fd(int fd);
int open_audit_fd_or_warn(void);
