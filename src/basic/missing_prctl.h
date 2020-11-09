/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/prctl.h>

/* 58319057b7847667f0c9585b9de0e8932b0fdb08 (4.3) */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47

#define PR_CAP_AMBIENT_IS_SET    1
#define PR_CAP_AMBIENT_RAISE     2
#define PR_CAP_AMBIENT_LOWER     3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
