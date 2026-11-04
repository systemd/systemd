/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#include "../fundamental/efi-firmware.h" /* IWYU pragma: export */

EFI_STATUS efi_firmware_match_by_fwid(const void *blob, size_t blob_len, const char *fwid);
