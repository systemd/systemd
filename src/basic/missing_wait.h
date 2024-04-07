/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/wait.h>

#include "macro.h"

#ifndef P_PIDFD
#  define P_PIDFD 3
#else
assert_cc(P_PIDFD == 3);
#endif
