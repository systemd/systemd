/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

EFI_STATUS efivar_erase_namespace(const EFI_GUID *vendor, const char16_t *const *keep);

/* Checks the LoaderFactoryResetVariables EFI variable, and if set erases all EFI variables in the LOADER
 * and SYSTEMD namespaces (with a few exceptions) and reboots, after asking the user for confirmation. Returns
 * only if no erasing took place. */
EFI_STATUS factory_reset_variables_process(void);
