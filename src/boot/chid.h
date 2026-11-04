/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include "efi.h"

#include "../fundamental/chid.h" /* IWYU pragma: export */

static inline const char* device_get_name(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_DEVICETREE:
                off = device->devicetree.name_offset;
                break;
        case DEVICE_TYPE_UEFI_FW:
                off = device->uefi_fw.name_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

static inline const char* device_get_compatible(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_DEVICETREE:
                off = device->devicetree.compatible_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

static inline const char* device_get_fwid(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_UEFI_FW:
                off = device->uefi_fw.fwid_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

EFI_STATUS chid_match(
                const void *hwid_buffer,
                size_t hwid_length,
                uint32_t match_type,
                const Device **ret_device);
