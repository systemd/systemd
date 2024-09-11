/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

bool smbios_in_hypervisor(void);

const char* smbios_find_oem_string(const char *name);
