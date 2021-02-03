/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef SD_BOOT
#include <efi.h>

typedef BOOLEAN sd_bool;
typedef CHAR16  sd_char;
typedef INTN    sd_int;
typedef UINTN   sd_size_t;

#define true    TRUE
#define false   FALSE
#else
#include <stdbool.h>
#include <stdint.h>

typedef bool    sd_bool;
typedef char    sd_char;
typedef int     sd_int;
typedef size_t  sd_size_t;
#endif
