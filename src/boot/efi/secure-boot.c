/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "secure-boot.h"
#include "util.h"

BOOLEAN secure_boot_enabled(void) {
        BOOLEAN secure;
        EFI_STATUS err;

        err = efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SecureBoot", &secure);

        return !EFI_ERROR(err) && secure;
}

#ifdef SBAT_DISTRO
static const char sbat[]
__attribute__((section (".sbat")))
__attribute__((__used__))
__attribute__((aligned(512))) = ""
"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
SBAT_PROJECT ",1,systemd EFI boot," SBAT_PROJECT "," PROJECT_VERSION "," PROJECT_URL "\n"
SBAT_PROJECT "." SBAT_DISTRO "," SBAT_DISTRO_GENERATION "," SBAT_DISTRO_SUMMARY "," SBAT_DISTRO_PKGNAME "," SBAT_DISTRO_VERSION "," SBAT_DISTRO_URL ;
#endif
