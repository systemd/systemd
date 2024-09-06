/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/prctl.h>

#include "macro.h"

/* 58319057b7847667f0c9585b9de0e8932b0fdb08 (4.3) */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47

#define PR_CAP_AMBIENT_IS_SET    1
#define PR_CAP_AMBIENT_RAISE     2
#define PR_CAP_AMBIENT_LOWER     3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/* b507808ebce23561d4ff8c2aa1fb949fe402bc61 (6.3) */
#ifndef PR_SET_MDWE
#  define PR_SET_MDWE 65
#else
assert_cc(PR_SET_MDWE == 65);
#endif

#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#  define PR_MDWE_REFUSE_EXEC_GAIN 1
#else
assert_cc(PR_MDWE_REFUSE_EXEC_GAIN == 1);
#endif

#ifndef PR_SET_MEMORY_MERGE
#  define PR_SET_MEMORY_MERGE 67
#else
assert_cc(PR_SET_MEMORY_MERGE == 67);
#endif
