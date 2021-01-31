/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, CHAR16 uuid[static 37]);
