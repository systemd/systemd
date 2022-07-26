/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <stdbool.h>
#include <uchar.h>

/* This TPM PCR is where we extend the sd-stub "payloads" into, before using them. i.e. the kernel ELF image,
 * embedded initrd, and so on. In contrast to PCR 4 (which also contains this data, given the whole
 * surrounding PE image is measured into it) this should be reasonably pre-calculatable, because it *only*
 * consists of static data from the kernel PE image. */
#define TPM_PCR_INDEX_KERNEL_IMAGE 11U

/* This TPM PCR is where sd-stub extends the kernel command line and any passed credentials into. */
#define TPM_PCR_INDEX_KERNEL_PARAMETERS 12U

/* sd-stub used to write the kernel command line/credentials into PCR 8, in systemd <= 250. Let's provide for
 * some compatibility. (Remove in 2023!) */
#if EFI_TPM_PCR_COMPAT
#define TPM_PCR_INDEX_KERNEL_PARAMETERS_COMPAT 8U
#else
#define TPM_PCR_INDEX_KERNEL_PARAMETERS_COMPAT UINT32_MAX
#endif

/* This TPM PCR is where we extend the initrd sysext images into which we pass to the booted kernel */
#define TPM_PCR_INDEX_INITRD_SYSEXTS 13U

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
