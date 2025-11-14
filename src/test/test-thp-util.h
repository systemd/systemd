/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "tests.h"

#define PR_THP_DISABLE_NOT_SET 0
#define PR_THP_DISABLE 1
#define PR_THP_DISABLE_EXCEPT_ADVISED (1 << 1)
