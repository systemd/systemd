/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "proto/simple-text-io.h"

enum {
        EFI_SHIFT_PRESSED   = EFI_RIGHT_SHIFT_PRESSED|EFI_LEFT_SHIFT_PRESSED,
        EFI_CONTROL_PRESSED = EFI_RIGHT_CONTROL_PRESSED|EFI_LEFT_CONTROL_PRESSED,
        EFI_ALT_PRESSED     = EFI_RIGHT_ALT_PRESSED|EFI_LEFT_ALT_PRESSED,
        EFI_LOGO_PRESSED    = EFI_RIGHT_LOGO_PRESSED|EFI_LEFT_LOGO_PRESSED,
};

#define KEYPRESS(keys, scan, uni) ((((uint64_t)keys) << 32) | (((uint64_t)scan) << 16) | (uni))
#define KEYCHAR(k) ((char16_t)(k))
#define CHAR_CTRL(c) ((c) - 'a' + 1)

enum {
        /* Console mode is a int32_t in EFI. We use int64_t to make room for our special values. */
        CONSOLE_MODE_RANGE_MIN = 0,
        CONSOLE_MODE_RANGE_MAX = INT32_MAX, /* This is just the theoretical limit. */
        CONSOLE_MODE_INVALID = -1,          /* UEFI uses -1 if the device is not in a valid text mode. */

        CONSOLE_MODE_80_25 = 0,             /* 80x25 is required by UEFI spec. */
        CONSOLE_MODE_80_50 = 1,             /* 80x50 may be supported. */
        CONSOLE_MODE_FIRMWARE_FIRST = 2,    /* First custom mode, if supported. */

        /* These are our own mode values that map to concrete values at runtime. */
        CONSOLE_MODE_KEEP = CONSOLE_MODE_RANGE_MAX + 1LL,
        CONSOLE_MODE_NEXT,
        CONSOLE_MODE_AUTO,
        CONSOLE_MODE_FIRMWARE_MAX, /* 'max' in config. */
};

EFI_STATUS console_key_read(uint64_t *key, uint64_t timeout_usec);
EFI_STATUS console_set_mode(int64_t mode);
EFI_STATUS console_query_mode(size_t *x_max, size_t *y_max);
EFI_STATUS query_screen_resolution(uint32_t *ret_width, uint32_t *ret_height);
