/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi.h"
#include "version.h"

/* Magic string for recognizing our own binaries */
DECLARE_NOALLOC_SECTION(".sdmagic", "#### LoaderInfo: systemd-addon " GIT_VERSION " ####");

/* This is intended to carry data, not to be executed */

EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table);
EFIAPI EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table) {
        return EFI_UNSUPPORTED;
}
