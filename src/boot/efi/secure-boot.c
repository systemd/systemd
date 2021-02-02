/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "secure-boot.h"
#include "util.h"

BOOLEAN secure_boot_enabled(void) {
        BOOLEAN secure;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);

        return !EFI_ERROR(err) && secure;
}
