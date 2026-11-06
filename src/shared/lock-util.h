/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#include "../basic/lock-util.h"      /* IWYU pragma: export */

int lock_generic_with_timeout(int fd, LockType type, int operation, usec_t timeout);
int make_lock_file_at_with_event(int dir_fd, const char *path, int operation, sd_event *event, LockFile *ret);
