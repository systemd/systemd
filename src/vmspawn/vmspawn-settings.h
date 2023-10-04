/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdint.h>

typedef enum ConfigFeature {
        CONFIG_FEATURE_AUTO,
        CONFIG_FEATURE_ENABLED,
        CONFIG_FEATURE_DISABLED,
        _CONFIG_FEATURE_MAX,
        _CONFIG_FEATURE_INVALID = -EINVAL,
} ConfigFeature;

typedef enum QemuFirmware {
        QEMU_FIRMWARE_DIRECT,
        QEMU_FIRMWARE_UEFI,
        QEMU_FIRMWARE_BIOS,
        _QEMU_FIRMWARE_MAX,
        _QEMU_FIRMWARE_INVALID = -EINVAL,
} QemuFirmware;

typedef enum SettingsMask {
        SETTING_START_MODE        = UINT64_C(1) << 0,
        SETTING_DIRECTORY         = UINT64_C(1) << 26,
        SETTING_CREDENTIALS       = UINT64_C(1) << 30,
        _SETTING_FORCE_ENUM_WIDTH = UINT64_MAX
} SettingsMask;

int parse_config_feature(const char *s, ConfigFeature *ret);
int parse_qemu_firmware(const char *s, QemuFirmware *ret);
