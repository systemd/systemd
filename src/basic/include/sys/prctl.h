/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <features.h>
#include <linux/prctl.h>        /* IWYU pragma: export */

#ifdef __GLIBC__
#include_next <sys/prctl.h>
#else
int prctl (int, ...);
#endif
