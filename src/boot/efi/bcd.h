/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

CHAR16 *get_bcd_title(uint8_t *bcd, UINTN bcd_len);
