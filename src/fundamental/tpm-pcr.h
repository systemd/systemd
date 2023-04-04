/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

/* The various TPM PCRs we measure into from sd-stub and sd-boot. */

/* This TPM PCR is where we extend the sd-stub "payloads" into, before using them. i.e. the kernel ELF image,
 * embedded initrd, and so on. In contrast to PCR 4 (which also contains this data, given the whole
 * surrounding PE image is measured into it) this should be reasonably pre-calculatable, because it *only*
 * consists of static data from the kernel PE image. */
#define TPM_PCR_INDEX_KERNEL_IMAGE 11U

/* This TPM PCR is where sd-stub extends the kernel command line and any passed credentials into. */
#define TPM_PCR_INDEX_KERNEL_PARAMETERS 12U

/* This TPM PCR is where we extend the initrd sysext images into which we pass to the booted kernel */
#define TPM_PCR_INDEX_INITRD_SYSEXTS 13U

/* This TPM PCR is where we measure the root fs volume key (and maybe /var/'s) if it is split off */
#define TPM_PCR_INDEX_VOLUME_KEY 15U

/* List of PE sections that have special meaning for us in unified kernels. This is the canonical order in
 * which we measure the sections into TPM PCR 11 (see above). PLEASE DO NOT REORDER! */
typedef enum UnifiedSection {
        UNIFIED_SECTION_LINUX,
        UNIFIED_SECTION_OSREL,
        UNIFIED_SECTION_CMDLINE,
        UNIFIED_SECTION_INITRD,
        UNIFIED_SECTION_SPLASH,
        UNIFIED_SECTION_DTB,
        UNIFIED_SECTION_PCRSIG,
        UNIFIED_SECTION_PCRPKEY,
        UNIFIED_SECTION_CMDLIST,
        _UNIFIED_SECTION_MAX,
} UnifiedSection;

extern const char* const unified_sections[_UNIFIED_SECTION_MAX + 1];

static inline bool unified_section_measure(UnifiedSection section) {
        /* Don't include the PCR signature in the PCR measurements, since they sign the expected result of
         * the measurement, and hence shouldn't be input to it. */
        return section >= 0 && section < _UNIFIED_SECTION_MAX && section != UNIFIED_SECTION_PCRSIG;
}
