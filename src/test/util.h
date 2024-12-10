/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Dummy EFI header for tests
 */
#pragma once

#include <stdlib.h>
#include <string.h>

#include "utf8.h"

#define xnew0(type, n) ((type *) calloc((n), sizeof(type)))
#define strlen8 strlen
#define xstrn8_to_16 utf8_to_utf16

#define log_error_status(status, fmt, ...) (puts(fmt), status)
#define efi_guid_equal(a, b) (memcmp((a), (b), sizeof(EFI_GUID)) == 0)
