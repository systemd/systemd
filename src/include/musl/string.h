/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <string.h>

char* strerror_r_gnu(int errnum, char *buf, size_t buflen);
#define strerror_r strerror_r_gnu
