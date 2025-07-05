/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/ioprio.h>       /* IWYU pragma: export */

#if !HAVE_IOPRIO_GET
int ioprio_get(int which, int who);
#endif

#if !HAVE_IOPRIO_SET
int ioprio_set(int which, int who, int ioprio);
#endif
