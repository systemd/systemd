/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

typedef enum SettingsMask {
        SETTING_START_MODE        = UINT64_C(1) << 0,
        SETTING_BIND_MOUNTS       = UINT64_C(1) << 11,
        SETTING_DIRECTORY         = UINT64_C(1) << 26,
        SETTING_CREDENTIALS       = UINT64_C(1) << 30,
        _SETTING_FORCE_ENUM_WIDTH = UINT64_MAX
} SettingsMask;
