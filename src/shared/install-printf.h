/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "install.h"
#include "unit-name.h"

int install_full_printf_internal(const UnitFileInstallInfo *i, const char *format, size_t max_length, const char *root, char **ret);

static inline int install_name_printf(const UnitFileInstallInfo *i, const char *format, const char *root, char **ret) {
        return install_full_printf_internal(i, format, UNIT_NAME_MAX, root, ret);
}
static inline int install_path_printf(const UnitFileInstallInfo *i, const char *format, const char *root, char **ret) {
        return install_full_printf_internal(i, format, PATH_MAX-1, root, ret);
}
