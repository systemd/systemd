/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2012 Lennart Poettering
  Copyright 2013 Kay Sievers
***/

#include <time-util.h>

int boot_timestamps(const dual_timestamp *n, dual_timestamp *firmware, dual_timestamp *loader);
