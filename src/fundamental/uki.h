/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

/* List of PE sections that have special meaning for us in unified kernels. This is the canonical order in
 * which we measure the sections into TPM PCR 11. PLEASE DO NOT REORDER! */
typedef enum UnifiedSection {
        UNIFIED_SECTION_LINUX,
        UNIFIED_SECTION_OSREL,
        UNIFIED_SECTION_CMDLINE,
        UNIFIED_SECTION_INITRD,
        UNIFIED_SECTION_SPLASH,
        UNIFIED_SECTION_DTB,
        UNIFIED_SECTION_UNAME,
        UNIFIED_SECTION_SBAT,
        UNIFIED_SECTION_PCRSIG,
        UNIFIED_SECTION_PCRPKEY,
        _UNIFIED_SECTION_MAX,
} UnifiedSection;

extern const char* const unified_sections[_UNIFIED_SECTION_MAX + 1];

static inline bool unified_section_measure(UnifiedSection section) {
        /* Don't include the PCR signature in the PCR measurements, since they sign the expected result of
         * the measurement, and hence shouldn't be input to it. */
        return section >= 0 && section < _UNIFIED_SECTION_MAX && section != UNIFIED_SECTION_PCRSIG;
}
