/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/wait.h> /* IWYU pragma: export */

/* since glibc-2.36 */
#ifndef P_PIDFD
#  define P_PIDFD 3
#endif
