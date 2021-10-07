/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef SD_BOOT
#include <efi.h>

typedef BOOLEAN sd_bool;
typedef CHAR16  sd_char;
typedef INTN    sd_int;
typedef UINTN   sd_size_t;
typedef UINT8   sd_uint8_t;
typedef UINT32  sd_uint32_t;
typedef UINT64  sd_uint64_t;
typedef VOID    sd_void;

#define true    TRUE
#define false   FALSE
#else
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef bool     sd_bool;
typedef char     sd_char;
typedef int      sd_int;
typedef size_t   sd_size_t;
typedef uint8_t  sd_uint8_t;
typedef uint32_t sd_uint32_t;
typedef uint64_t sd_uint64_t;
typedef void     sd_void;
#endif
