/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "tpm-pcr.h"

const char* const unified_sections[_UNIFIED_SECTION_MAX + 1] = {
        [UNIFIED_SECTION_LINUX]   = ".linux",
        [UNIFIED_SECTION_OSREL]   = ".osrel",
        [UNIFIED_SECTION_CMDLINE] = ".cmdline",
        [UNIFIED_SECTION_INITRD]  = ".initrd",
        [UNIFIED_SECTION_SPLASH]  = ".splash",
        [UNIFIED_SECTION_DTB]     = ".dtb",
        [UNIFIED_SECTION_PCRSIG]  = ".pcrsig",
        [UNIFIED_SECTION_PCRPKEY] = ".pcrpkey",
        NULL,
};
