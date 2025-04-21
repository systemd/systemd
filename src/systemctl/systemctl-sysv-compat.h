/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum SysVUnitEnableState {
        SYSV_UNIT_NOT_FOUND = 0,
        SYSV_UNIT_DISABLED,
        SYSV_UNIT_ENABLED,
} SysVUnitEnableState;

int enable_sysv_units(const char *verb, char **args);
