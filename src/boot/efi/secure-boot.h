/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include "efivars-fundamental.h"

BOOLEAN secure_boot_enabled(void);
SecureBootMode secure_boot_mode(void);
