/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int hwclock_get(const char *rtc_device, struct tm *tm);
int hwclock_set(const char *rtc_device, const struct tm *tm);
