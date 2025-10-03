/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <time.h>

char* strptime_fallback(const char *s, const char *format, struct tm *tm);
#define strptime strptime_fallback
