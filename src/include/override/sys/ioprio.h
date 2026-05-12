/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/ioprio.h>       /* IWYU pragma: export */

int missing_ioprio_get(int which, int who);
#define ioprio_get missing_ioprio_get

int missing_ioprio_set(int which, int who, int ioprio);
#define ioprio_set missing_ioprio_set
