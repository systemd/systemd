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
        UNIFIED_SECTION_UCODE,
        UNIFIED_SECTION_SPLASH,
        UNIFIED_SECTION_DTB,
        UNIFIED_SECTION_UNAME,
        UNIFIED_SECTION_SBAT,
        UNIFIED_SECTION_PCRSIG,
        UNIFIED_SECTION_PCRPKEY,
        UNIFIED_SECTION_PROFILE,
        UNIFIED_SECTION_DTBAUTO,
        UNIFIED_SECTION_HWIDS,
        UNIFIED_SECTION_EFIFW,
        _UNIFIED_SECTION_MAX,
} UnifiedSection;

extern const char* const unified_sections[_UNIFIED_SECTION_MAX + 1];

static inline bool unified_section_measure(UnifiedSection section) {
        /* Don't include the PCR signature in the PCR measurements, since they sign the expected result of
         * the measurement, and hence shouldn't be input to it. */
        return section >= 0 && section < _UNIFIED_SECTION_MAX && section != UNIFIED_SECTION_PCRSIG;
}

/* Max number of profiles per UKI */
#define UNIFIED_PROFILES_MAX 256U

/* The native PE machine type, if known, for a full list see:
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types */
#ifndef _IMAGE_FILE_MACHINE_NATIVE
#  if defined(__x86_64__)
#    define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x8664)
#  elif defined(__i386__)
#    define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x014c)
#  elif defined(__ia64__)
#    define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x0200)
#  elif defined(__aarch64__)
#    define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0xaa64)
#  elif defined(__arm__)
#    define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x01c0)
#  elif defined(__riscv)
#    if __SIZEOF_POINTER__ == 4
#      define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x5032)
#    elif __SIZEOF_POINTER__ == 8
#      define _IMAGE_FILE_MACHINE_NATIVE UINT16_C(0x5064)
#    endif
#  endif
#endif
