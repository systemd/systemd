/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sbat.h"
#include "secure-boot.h"
#include "util.h"

bool secure_boot_enabled(void) {
        bool secure;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);

        return err == EFI_SUCCESS && secure;
}

SecureBootMode secure_boot_mode(void) {
        bool secure, audit = false, deployed = false, setup = false;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);
        if (err != EFI_SUCCESS)
                return SECURE_BOOT_UNSUPPORTED;

        /* We can assume false for all these if they are abscent (AuditMode and
         * DeployedMode may not exist on older firmware). */
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"AuditMode", &audit);
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"DeployedMode", &deployed);
        (void) efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SetupMode", &setup);

        return decode_secure_boot_mode(secure, audit, deployed, setup);
}

#ifdef SBAT_DISTRO
static const char sbat[] _used_ _section_(".sbat") = SBAT_SECTION_TEXT;
#endif
