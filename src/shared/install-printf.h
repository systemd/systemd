/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "install.h"
#include "unit-name.h"

int install_full_printf_internal(const UnitFileInstallInfo *i, const char *format, size_t max_length, char **ret);
static inline int install_name_printf(const UnitFileInstallInfo *i, const char *format, char **ret) {
        return install_full_printf_internal(i, format, UNIT_NAME_MAX, ret);
}
static inline int install_path_printf(const UnitFileInstallInfo *i, const char *format, char **ret) {
        return install_full_printf_internal(i, format, PATH_MAX-1, ret);
}
