/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

typedef enum FactoryResetVariablesMode {
        FACTORY_RESET_VARIABLES_ASK, /* Ask the user interactively before erasing */
        FACTORY_RESET_VARIABLES_YES, /* Erase without asking */
        FACTORY_RESET_VARIABLES_NO,  /* Never erase, just drop the request */
        _FACTORY_RESET_VARIABLES_MAX,
} FactoryResetVariablesMode;

DECLARE_STRING_TABLE_LOOKUP(factory_reset_variables_mode, FactoryResetVariablesMode);

EFI_STATUS efivar_erase_namespace(const EFI_GUID *vendor, const char16_t *const *keep);

/* Checks the LoaderFactoryResetVariables EFI variable, and if set erases all EFI variables in the LOADER
 * and SYSTEMD namespaces (with a few exceptions) and reboots. Returns only if no erasing took place. */
EFI_STATUS factory_reset_variables_process(FactoryResetVariablesMode mode);
