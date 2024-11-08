/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "uki.h"

const char* const unified_sections[_UNIFIED_SECTION_MAX + 1] = {
        /* These section names must fit in 8ch (excluding any trailing NUL) as per PE spec for executables:
         * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
         * (Note that PE *object* files may have longer section names (via indirection in the string table) but
         * this is not allowed for PE *executables*, which UKIs are.) */
        [UNIFIED_SECTION_LINUX]   = ".linux",
        [UNIFIED_SECTION_OSREL]   = ".osrel",
        [UNIFIED_SECTION_CMDLINE] = ".cmdline",
        [UNIFIED_SECTION_INITRD]  = ".initrd",
        [UNIFIED_SECTION_UCODE]   = ".ucode",
        [UNIFIED_SECTION_SPLASH]  = ".splash",
        [UNIFIED_SECTION_DTB]     = ".dtb",
        [UNIFIED_SECTION_UNAME]   = ".uname",
        [UNIFIED_SECTION_SBAT]    = ".sbat",
        [UNIFIED_SECTION_PCRSIG]  = ".pcrsig",
        [UNIFIED_SECTION_PCRPKEY] = ".pcrpkey",
        [UNIFIED_SECTION_PROFILE] = ".profile",
        [UNIFIED_SECTION_DTBAUTO] = ".dtbauto",
        [UNIFIED_SECTION_HWIDS]   = ".hwids",
        [UNIFIED_SECTION_EFIFW]   = ".efifw",
        NULL,
};
