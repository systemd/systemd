/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include "efivars-fundamental.h"

typedef enum {
        ENROLL_OFF,         /* no Secure Boot key enrollment whatsoever, even manual entries are not generated */
        ENROLL_MANUAL,      /* Secure Boot key enrollment is strictly manual: manual entries are generated and need to be selected by the user */
        ENROLL_FORCE,       /* Secure Boot key enrollment may be automatic if it is available but might not be safe */
} secure_boot_enroll;

bool secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);

EFI_STATUS secure_boot_enroll_at(EFI_FILE *root_dir, const char16_t *path);
