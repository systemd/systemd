/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <time-util.h>

int boot_timestamps(const dual_timestamp *n, dual_timestamp *firmware, dual_timestamp *loader);
