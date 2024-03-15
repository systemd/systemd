/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/wait.h>

#include "macro.h"

#ifndef P_PIDFD
#  define P_PIDFD 3
#else
static_assert(P_PIDFD == 3);
#endif
