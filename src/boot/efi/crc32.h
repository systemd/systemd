/* SPDX-License-Identifier: LicenseRef-crc32-no-restriction */
#pragma once

#include <efi.h>
#include <efilib.h>

UINT32 crc32(UINT32 seed, const VOID *buf, UINTN len);
UINT32 crc32_exclude_offset(UINT32 seed, const VOID *buf, UINTN len, UINTN exclude_off, UINTN exclude_len);
