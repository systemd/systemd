/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <uchar.h>

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, char16_t uuid[static 37]);
