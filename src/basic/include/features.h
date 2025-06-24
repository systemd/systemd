/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <features.h>

/* Most libc headers includes features.h.
 * Let's define assert_cc() here, to make it usable in our libc header wrappers. */
#include <_sd_assert_cc.h>
