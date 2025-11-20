/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int hwclock_get(struct tm *tm);
int hwclock_set(const struct tm *tm);
