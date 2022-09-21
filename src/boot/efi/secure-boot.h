/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#include "efivars-fundamental.h"
#include "missing_efi.h"

typedef enum {
        ENROLL_OFF,         /* no Secure Boot key enrollment whatsoever, even manual entries are not generated */
        ENROLL_MANUAL,      /* Secure Boot key enrollment is strictly manual: manual entries are generated and need to be selected by the user */
        ENROLL_FORCE,       /* Secure Boot key enrollment may be automatic if it is available but might not be safe */
} secure_boot_enroll;

bool secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);

EFI_STATUS secure_boot_enroll_at(EFI_FILE *root_dir, const char16_t *path);

typedef struct {
        void *hook;

        /* End of EFI_SECURITY_ARCH(2)_PROTOCOL. The rest is our own protocol instance data. */

        EFI_HANDLE original_handle;
        union {
                void *original;
                EFI_SECURITY_ARCH_PROTOCOL *original_security;
                EFI_SECURITY2_ARCH_PROTOCOL *original_security2;
        };

        /* Used by the stub to identify the embedded image. */
        const void *payload;
        size_t payload_len;
        const EFI_DEVICE_PATH *payload_device_path;
} SecurityOverride;

void install_security_override(SecurityOverride *override, SecurityOverride *override2);
void uninstall_security_override(SecurityOverride *override, SecurityOverride *override2);
