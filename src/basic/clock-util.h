/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
***/

#include <time.h>

int clock_is_localtime(const char* adjtime_path);
int clock_set_timezone(int *min);
int clock_reset_timewarp(void);
int clock_get_hwclock(struct tm *tm);
int clock_set_hwclock(const struct tm *tm);
int clock_apply_epoch(void);
