/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "install.h"
#include "unit-name.h"

int install_name_printf(
                LookupScope scope,
                const UnitFileInstallInfo *info,
                const char *format,
                char **ret);
