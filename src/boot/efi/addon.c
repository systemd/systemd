/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi.h"

/* This is intended to carry data, not to be executed */

EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table);
EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table) {
    return EFI_SECURITY_VIOLATION;
}
