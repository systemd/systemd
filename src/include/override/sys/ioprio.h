/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/ioprio.h>       /* IWYU pragma: export */

#if !HAVE_IOPRIO_GET
int missing_ioprio_get(int which, int who);
#  define ioprio_get missing_ioprio_get
#endif

#if !HAVE_IOPRIO_SET
int missing_ioprio_set(int which, int who, int ioprio);
#  define ioprio_set missing_ioprio_set
#endif
