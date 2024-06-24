/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#if ENABLE_TPM

bool tpm_present(void);

/* Routines for boot-time TPM PCR measurement as well as submitting an event log entry about it. The latter
 * can be done with two different event log record types. For old stuff we use EV_IPL (which is legacy, and
 * not great to recognize properly during PCR validation). For new stuff we use properly tagged
 * EV_EVENT_TAG record. */

/* Old stuff is logged as EV_IPL */
EFI_STATUS tpm_log_ipl_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured);
EFI_STATUS tpm_log_ipl_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const
char *description, bool *ret_measured);

/* New stuff is logged as EV_EVENT_TAG */
EFI_STATUS tpm_log_tagged_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, uint32_t event_id, const char16_t *description, bool *ret_measured);

EFI_STATUS tpm_log_load_options(const char16_t *cmdline, bool *ret_measured);

#else

static inline bool tpm_present(void) {
        return false;
}

static inline EFI_STATUS tpm_log_ipl_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        if (ret_measured)
                *ret_measured = false;
        return EFI_SUCCESS;
}

static inline EFI_STATUS tpm_log_ipl_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char *description, bool *ret_measured) {
        if (ret_measured)
                *ret_measured = false;
        return EFI_SUCCESS;
}

static inline EFI_STATUS tpm_log_tagged_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, uint32_t event_id, const char16_t *description, bool *ret_measured) {
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
