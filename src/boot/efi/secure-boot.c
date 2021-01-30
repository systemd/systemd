/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "secure-boot.h"
#include "util.h"

BOOLEAN secure_boot_enabled(void) {
        _cleanup_freepool_ CHAR8 *b = NULL;
        UINTN size;

        if (efivar_get_raw(EFI_GLOBAL_GUID, L"SecureBoot", &b, &size) == EFI_SUCCESS)
                return *b > 0;

        return FALSE;
}
