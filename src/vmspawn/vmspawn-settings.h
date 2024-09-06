/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdint.h>

#include "macro.h"

typedef enum ConsoleMode {
        CONSOLE_INTERACTIVE,    /* ptyfwd */
        CONSOLE_READ_ONLY,      /* ptyfwd, but in read-only mode */
        CONSOLE_NATIVE,         /* qemu's native TTY handling */
        CONSOLE_GUI,            /* qemu's graphical UI */
        _CONSOLE_MODE_MAX,
        _CONSOLE_MODE_INVALID = -EINVAL,
} ConsoleMode;

typedef enum SettingsMask {
        SETTING_START_MODE        = UINT64_C(1) << 0,
        SETTING_MACHINE_ID        = UINT64_C(1) << 6,
        SETTING_BIND_MOUNTS       = UINT64_C(1) << 11,
        SETTING_DIRECTORY         = UINT64_C(1) << 26,
        SETTING_CREDENTIALS       = UINT64_C(1) << 30,
        _SETTING_FORCE_ENUM_WIDTH = UINT64_MAX
} SettingsMask;

const char* console_mode_to_string(ConsoleMode m) _const_;
ConsoleMode console_mode_from_string(const char *s) _pure_;
