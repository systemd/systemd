/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <stdlib.h>

long long strtoll_fallback(const char *nptr, char **endptr, int base);
#define strtoll strtoll_fallback
