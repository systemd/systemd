/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "efivars-fundamental.h"

typedef enum {
        ENROLL_OFF,         /* no Secure Boot key enrollment whatsoever, even manual entries are not generated */
        ENROLL_MANUAL,      /* Secure Boot key enrollment is strictly manual: manual entries are generated and need to be selected by the user */
        ENROLL_IF_SAFE,     /* Automatically enroll if it is safe (if we are running inside a VM, for example). */
        ENROLL_FORCE,       /* Secure Boot key enrollment may be automatic if it is available but might not be safe */
} secure_boot_enroll;

bool secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);

EFI_STATUS secure_boot_enroll_at(EFI_FILE *root_dir, const char16_t *path, bool force);

typedef bool (*security_validator_t)(
                const void *ctx,
                const EFI_DEVICE_PATH *device_path,
                const void *file_buffer,
                size_t file_size);

void install_security_override(security_validator_t validator, const void *validator_ctx);
void uninstall_security_override(void);
