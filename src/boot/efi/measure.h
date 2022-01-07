/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#if ENABLE_TPM

BOOLEAN tpm_present(void);
EFI_STATUS tpm_log_event(UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const CHAR16 *description);
EFI_STATUS tpm_log_load_options(const CHAR16 *cmdline);

#else

static inline BOOLEAN tpm_present(void) {
        return FALSE;
}
static inline EFI_STATUS tpm_log_event(UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const CHAR16 *description) {
        return EFI_SUCCESS;
}
static inline EFI_STATUS tpm_log_load_options(const CHAR16 *cmdline) {
        return EFI_SUCCESS;
}

#endif
