/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

BOOLEAN secure_boot_enabled(void);

EFI_STATUS setup_secure_boot(EFI_FILE *root_dir);
