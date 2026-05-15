/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/ioprio.h>       /* IWYU pragma: export */

int ioprio_get_shim(int which, int who);
#define ioprio_get ioprio_get_shim

int ioprio_set_shim(int which, int who, int ioprio);
#define ioprio_set ioprio_set_shim
