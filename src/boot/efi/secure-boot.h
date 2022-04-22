/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#include "boot.h"
#include "efivars-fundamental.h"

BOOLEAN secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);

EFI_STATUS secure_boot_enroll(EFI_FILE *root_dir, Config *config, ConfigEntry *entry);
