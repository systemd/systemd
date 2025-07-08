/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <signal.h>

#if !HAVE_RT_TGSIGQUEUEINFO
int missing_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
#  define rt_tgsigqueueinfo missing_rt_tgsigqueueinfo
#endif
