/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <stdbool.h>
#include <uchar.h>

#if ENABLE_TPM

bool tpm_present(void);
EFI_STATUS tpm_log_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const char16_t *description, bool *ret_measured);
EFI_STATUS tpm_log_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const char *description, bool *ret_measured);
EFI_STATUS tpm_log_load_options(const char16_t *cmdline, bool *ret_measured);

#else

static inline bool tpm_present(void) {
        return false;
}

static inline EFI_STATUS tpm_log_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const char16_t *description, bool *ret_measured) {
        if (ret_measured)
                *ret_measured = false;
        return EFI_SUCCESS;
}

static inline EFI_STATUS tpm_log_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const char *description, bool *ret_measured) {
        if (ret_measured)
                *ret_measured = false;
        return EFI_SUCCESS;
}

static inline EFI_STATUS tpm_log_load_options(const char16_t *cmdline, bool *ret_measured) {
        if (ret_measured)
                *ret_measured = false;
        return EFI_SUCCESS;
}

#endif
