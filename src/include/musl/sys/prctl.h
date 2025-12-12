/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/prctl.h>     /* IWYU pragma: export */

/* musl's sys/prctl.h does not include linux/prctl.h, and also we cannot include with linux/prctl.h.
 * Hence, we need to provide some missing definitions. */

#ifndef PR_SET_MDWE
#define PR_SET_MDWE  65
#endif

#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN  (1UL << 0)
#endif

#ifndef PR_SET_MEMORY_MERGE
#define PR_SET_MEMORY_MERGE  67
#endif
