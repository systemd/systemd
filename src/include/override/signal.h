/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <signal.h>        /* IWYU pragma: export */

int rt_tgsigqueueinfo_shim(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
#define rt_tgsigqueueinfo rt_tgsigqueueinfo_shim
