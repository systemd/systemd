/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

/* While we are chmod()ing a directory tree, we set the top-level UID base to this "busy" base, so that we can always
 * recognize trees we are were chmod()ing recursively and got interrupted in */
#define UID_BUSY_BASE ((uid_t) UINT32_C(0xFFFE0000))
#define UID_BUSY_MASK ((uid_t) UINT32_C(0xFFFF0000))
