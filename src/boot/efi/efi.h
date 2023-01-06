/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "macro-fundamental.h"

#if SD_BOOT
/* uchar.h/wchar.h are not suitable for freestanding environments. */
typedef __WCHAR_TYPE__ wchar_t;
typedef __CHAR16_TYPE__ char16_t;
typedef __CHAR32_TYPE__ char32_t;

/* Let's be paranoid and do some sanity checks. */
assert_cc(__STDC_HOSTED__ == 0);
assert_cc(sizeof(bool) == 1);
assert_cc(sizeof(uint8_t) == 1);
assert_cc(sizeof(uint16_t) == 2);
assert_cc(sizeof(uint32_t) == 4);
assert_cc(sizeof(uint64_t) == 8);
assert_cc(sizeof(wchar_t) == 2);
assert_cc(sizeof(char16_t) == 2);
assert_cc(sizeof(char32_t) == 4);
assert_cc(sizeof(size_t) == sizeof(void *));
assert_cc(sizeof(size_t) == sizeof(uintptr_t));
#else
#  include <uchar.h>
#  include <wchar.h>
#endif

/* We use size_t/ssize_t to represent UEFI UINTN/INTN. */
typedef size_t EFI_STATUS;
typedef intptr_t ssize_t;

typedef void* EFI_HANDLE;
typedef void* EFI_EVENT;
typedef size_t EFI_TPL;
typedef uint64_t EFI_LBA;
typedef uint64_t EFI_PHYSICAL_ADDRESS;

#if defined(__x86_64__)
#  define EFIAPI __attribute__((ms_abi))
#else
#  define EFIAPI
#endif

#if __SIZEOF_POINTER__ == 8
#  define EFI_ERROR_MASK 0x8000000000000000ULL
#elif __SIZEOF_POINTER__ == 4
#  define EFI_ERROR_MASK 0x80000000ULL
#else
#  error Unsupported pointer size
#endif

#define EFIWARN(s) ((EFI_STATUS) s)
#define EFIERR(s) ((EFI_STATUS) (s | EFI_ERROR_MASK))

#define EFI_SUCCESS               EFIWARN(0)
#define EFI_WARN_UNKNOWN_GLYPH    EFIWARN(1)
#define EFI_WARN_DELETE_FAILURE   EFIWARN(2)
#define EFI_WARN_WRITE_FAILURE    EFIWARN(3)
#define EFI_WARN_BUFFER_TOO_SMALL EFIWARN(4)
#define EFI_WARN_STALE_DATA       EFIWARN(5)
#define EFI_WARN_FILE_SYSTEM      EFIWARN(6)
#define EFI_WARN_RESET_REQUIRED   EFIWARN(7)

#define EFI_LOAD_ERROR           EFIERR(1)
#define EFI_INVALID_PARAMETER    EFIERR(2)
#define EFI_UNSUPPORTED          EFIERR(3)
#define EFI_BAD_BUFFER_SIZE      EFIERR(4)
#define EFI_BUFFER_TOO_SMALL     EFIERR(5)
#define EFI_NOT_READY            EFIERR(6)
#define EFI_DEVICE_ERROR         EFIERR(7)
#define EFI_WRITE_PROTECTED      EFIERR(8)
#define EFI_OUT_OF_RESOURCES     EFIERR(9)
#define EFI_VOLUME_CORRUPTED     EFIERR(10)
#define EFI_VOLUME_FULL          EFIERR(11)
#define EFI_NO_MEDIA             EFIERR(12)
#define EFI_MEDIA_CHANGED        EFIERR(13)
#define EFI_NOT_FOUND            EFIERR(14)
#define EFI_ACCESS_DENIED        EFIERR(15)
#define EFI_NO_RESPONSE          EFIERR(16)
#define EFI_NO_MAPPING           EFIERR(17)
#define EFI_TIMEOUT              EFIERR(18)
#define EFI_NOT_STARTED          EFIERR(19)
#define EFI_ALREADY_STARTED      EFIERR(20)
#define EFI_ABORTED              EFIERR(21)
#define EFI_ICMP_ERROR           EFIERR(22)
#define EFI_TFTP_ERROR           EFIERR(23)
#define EFI_PROTOCOL_ERROR       EFIERR(24)
#define EFI_INCOMPATIBLE_VERSION EFIERR(25)
#define EFI_SECURITY_VIOLATION   EFIERR(26)
#define EFI_CRC_ERROR            EFIERR(27)
#define EFI_END_OF_MEDIA         EFIERR(28)
#define EFI_ERROR_RESERVED_29    EFIERR(29)
#define EFI_ERROR_RESERVED_30    EFIERR(30)
#define EFI_END_OF_FILE          EFIERR(31)
#define EFI_INVALID_LANGUAGE     EFIERR(32)
#define EFI_COMPROMISED_DATA     EFIERR(33)
#define EFI_IP_ADDRESS_CONFLICT  EFIERR(34)
#define EFI_HTTP_ERROR           EFIERR(35)

typedef struct {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t Data4[8];
} EFI_GUID;

#define GUID_DEF(d1, d2, d3, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7, d4_8) \
    { d1, d2, d3, { d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7, d4_8 } }

/* Creates a EFI_GUID pointer suitable for EFI APIs. Use of const allows the compiler to merge multiple
 * uses (although, currently compilers do that regardless). Most EFI APIs declare their EFI_GUID input
 * as non-const, but almost all of them are in fact const. */
#define MAKE_GUID_PTR(name) ((EFI_GUID *) &(const EFI_GUID) name##_GUID)

/* These allow MAKE_GUID_PTR() to work without requiring an extra _GUID in the passed name. We want to
 * keep the GUID definitions in line with the UEFI spec. */
#define EFI_GLOBAL_VARIABLE_GUID EFI_GLOBAL_VARIABLE
#define EFI_FILE_INFO_GUID EFI_FILE_INFO_ID

/* These are common enough to warrant forward declaration. We also give them a
 * shorter name for convenience. */
typedef struct EFI_FILE_PROTOCOL EFI_FILE;
typedef struct EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH;

#include "proto/tables.h"
