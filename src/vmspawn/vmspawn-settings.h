/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum ImageFormat {
        IMAGE_FORMAT_RAW,
        IMAGE_FORMAT_QCOW2,
        _IMAGE_FORMAT_MAX,
        _IMAGE_FORMAT_INVALID = -EINVAL,
} ImageFormat;

typedef struct ExtraDrive {
        char *path;
        ImageFormat format;
} ExtraDrive;

typedef struct ExtraDriveContext {
        ExtraDrive *drives;
        size_t n_drives;
} ExtraDriveContext;

void extra_drive_context_done(ExtraDriveContext *ctx);

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
        SETTING_EPHEMERAL         = UINT64_C(1) << 24,
        SETTING_DIRECTORY         = UINT64_C(1) << 26,
        SETTING_CREDENTIALS       = UINT64_C(1) << 30,
        _SETTING_FORCE_ENUM_WIDTH = UINT64_MAX
} SettingsMask;

DECLARE_STRING_TABLE_LOOKUP(console_mode, ConsoleMode);
DECLARE_STRING_TABLE_LOOKUP(image_format, ImageFormat);
