/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-util.h"
#include "shared-forward.h"

typedef struct ExtraDrive {
        char *path;
        ImageFormat format;
        DiskType disk_type;
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
        CONSOLE_HEADLESS,       /* no console */
        _CONSOLE_MODE_MAX,
        _CONSOLE_MODE_INVALID = -EINVAL,
} ConsoleMode;

typedef enum ConsoleTransport {
        CONSOLE_TRANSPORT_VIRTIO,       /* virtio-serial (hvc0) */
        CONSOLE_TRANSPORT_SERIAL,       /* regular serial port (ttyS0/ttyAMA0) */
        _CONSOLE_TRANSPORT_MAX,
        _CONSOLE_TRANSPORT_INVALID = -EINVAL,
} ConsoleTransport;

typedef enum Firmware {
        FIRMWARE_UEFI,  /* load OVMF firmware */
        FIRMWARE_BIOS,  /* don't load OVMF, let qemu use its built-in BIOS (e.g. SeaBIOS on x86) */
        FIRMWARE_NONE,  /* no firmware at all, requires --linux= for direct kernel boot */
        _FIRMWARE_MAX,
        _FIRMWARE_INVALID = -EINVAL,
} Firmware;

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
DECLARE_STRING_TABLE_LOOKUP(console_transport, ConsoleTransport);
DECLARE_STRING_TABLE_LOOKUP(firmware, Firmware);
