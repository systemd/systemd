/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#define SD_LOGIND_DEFAULT_INHIBITORS     (UINT64_C(0))
#define SD_LOGIND_ROOT_CHECK_INHIBITORS  (UINT64_C(1) << 0)

#define SD_LOGIND_FLAGS_ALL              (SD_LOGIND_ROOT_CHECK_INHIBITORS)
