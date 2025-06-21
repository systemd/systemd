/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/kcmp.h>         /* IWYU pragma: export */

#include "forward.h"

#if !HAVE_KCMP
int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
#endif
