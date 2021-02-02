/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if defined SD_BOOT
#include <efi.h>

typedef CHAR16  sd_char;
typedef INTN    sd_int;
#else
typedef char sd_char;
typedef int  sd_int;
#endif

sd_int strverscmp_improved(const sd_char *a, const sd_char *b);
